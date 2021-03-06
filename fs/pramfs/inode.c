/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
 *
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include "pram.h"
#include "xattr.h"
#include "xip.h"
#include "acl.h"

struct backing_dev_info pram_backing_dev_info __read_mostly = {
	.ra_pages       = 0,    /* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};

/*
 * allocate a data block for inode and return it's absolute blocknr.
 * Zeroes out the block if zero set. Increments inode->i_blocks.
 */
static int pram_new_data_block(struct inode *inode, unsigned long *blocknr,
			       int zero)
{
	int errval = pram_new_block(inode->i_sb, blocknr, zero);

	if (!errval) {
		struct pram_inode *pi = pram_get_inode(inode->i_sb,
							inode->i_ino);
		inode->i_blocks++;
		pram_memunlock_inode(inode->i_sb, pi);
		pi->i_blocks = cpu_to_be32(inode->i_blocks);
		pram_memlock_inode(inode->i_sb, pi);
	}

	return errval;
}

/*
 * find the offset to the block represented by the given inode's file
 * relative block number.
 */
u64 pram_find_data_block(struct inode *inode, unsigned long file_blocknr)
{
	struct super_block *sb = inode->i_sb;
	struct pram_inode *pi;
	u64 *row; /* ptr to row block */
	u64 *col; /* ptr to column blocks */
	u64 bp = 0;
	unsigned int i_row, i_col;
	unsigned int N = sb->s_blocksize >> 3; /* num block ptrs per block */
	unsigned int Nbits = sb->s_blocksize_bits - 3;

	pi = pram_get_inode(sb, inode->i_ino);

	i_row = file_blocknr >> Nbits;
	i_col  = file_blocknr & (N-1);

	row = pram_get_block(sb, be64_to_cpu(pi->i_type.reg.row_block));
	if (row) {
		col = pram_get_block(sb, be64_to_cpu(row[i_row]));
		if (col)
			bp = be64_to_cpu(col[i_col]);
	}

	return bp;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
int pram_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct super_block *sb = inode->i_sb;
	struct pram_inode *pi = pram_get_inode(sb, inode->i_ino);
	int N = sb->s_blocksize >> 3; /* num block ptrs per block */
	int first_row_index, last_row_index, i, j;
	unsigned long first_blocknr, last_blocknr, blocks = 0, offset_in_block;
	u64 *row; /* ptr to row block */
	u64 *col; /* ptr to column blocks */
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !pi->i_type.reg.row_block) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & (sb->s_blocksize - 1);

	first_blocknr = *offset >> sb->s_blocksize_bits;
	last_blocknr = inode->i_size >> sb->s_blocksize_bits;

	first_row_index = first_blocknr >> (sb->s_blocksize_bits - 3);
	last_row_index  = last_blocknr >> (sb->s_blocksize_bits - 3);

	row = pram_get_block(sb, be64_to_cpu(pi->i_type.reg.row_block));

	for (i = first_row_index; i <= last_row_index; i++) {
		int first_col_index = (i == first_row_index) ?
			first_blocknr & (N-1) : 0;
		int last_col_index = (i == last_row_index) ?
			last_blocknr & (N-1) : N-1;

		if (!row[i]) {
			hole_found = 1;
			if (!hole)
				blocks += sb->s_blocksize >> 3;
			continue;
		}

		col = pram_get_block(sb, be64_to_cpu(row[i]));

		for (j = first_col_index; j <= last_col_index; j++) {

			if (col[j]) {
				data_found = 1;
				if (!hole)
					goto out;
			} else
				hole_found = 1;

			if (!hole_found || !hole)
				blocks++;
		}
		cond_resched();
	}
 out:
	/* Searching data but only hole found till the end */
	if (!hole && !data_found && hole_found)
		return -ENXIO;

	if (data_found && !hole_found) {
		/* Searching data but we are alredy into them */
		if (!hole)
			return 0;
		/* Searching hole but only data found, go to the end */
		else {
			*offset = inode->i_size;
			return 0;
		}
	}

	/* Searching for hole, hole found and starting inside an hole */
	if (hole && hole_found && !blocks) {
			/* we found data after it */
			if (data_found)
				return 0;
			else {
				/* last hole */
				*offset = inode->i_size;
				return 0;
			}
	}

	if (offset_in_block) {
		blocks--;
		*offset += (blocks << sb->s_blocksize_bits) +
					(sb->s_blocksize - offset_in_block);
	} else
		*offset += blocks << sb->s_blocksize_bits;

	return 0;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void __pram_truncate_blocks(struct inode *inode, loff_t start,
				   loff_t end)
{
	struct super_block *sb = inode->i_sb;
	struct pram_inode *pi = pram_get_inode(sb, inode->i_ino);
	int N = sb->s_blocksize >> 3; /* num block ptrs per block */
	int Nbits = sb->s_blocksize_bits - 3;
	int first_row_index, last_row_index, i, j;
	unsigned long blocknr, first_blocknr, last_blocknr;
	unsigned int freed = 0;
	u64 *row; /* ptr to row block */
	u64 *col; /* ptr to column blocks */

	if (!pi->i_type.reg.row_block)
		return;

	first_blocknr = (start + sb->s_blocksize - 1) >> sb->s_blocksize_bits;

	if (pi->i_flags & cpu_to_be32(PRAM_EOFBLOCKS_FL))
		last_blocknr = (1UL << (2*sb->s_blocksize_bits - 6)) - 1;
	else
		last_blocknr = end >> sb->s_blocksize_bits;

	if (first_blocknr > last_blocknr)
		return;

	first_row_index = first_blocknr >> Nbits;
	last_row_index  = last_blocknr >> Nbits;

	row = pram_get_block(sb, be64_to_cpu(pi->i_type.reg.row_block));

	for (i = first_row_index; i <= last_row_index; i++) {
		int first_col_index = (i == first_row_index) ?
			first_blocknr & (N-1) : 0;
		int last_col_index = (i == last_row_index) ?
			last_blocknr & (N-1) : N-1;

		if (unlikely(!row[i]))
			continue;

		col = pram_get_block(sb, be64_to_cpu(row[i]));

		for (j = first_col_index; j <= last_col_index; j++) {

			if (unlikely(!col[j]))
				continue;

			blocknr = pram_get_blocknr(sb, be64_to_cpu(col[j]));
			pram_free_block(sb, blocknr);
			freed++;
			pram_memunlock_block(sb, col);
			col[j] = 0;
			pram_memlock_block(sb, col);
		}

		cond_resched();

		if (first_col_index == 0) {
			blocknr = pram_get_blocknr(sb, be64_to_cpu(row[i]));
			pram_free_block(sb, blocknr);
			pram_memunlock_block(sb, row);
			row[i] = 0;
			pram_memlock_block(sb, row);
		}
	}

	inode->i_blocks -= freed;

	if (start == 0) {
		blocknr = pram_get_blocknr(sb,
					be64_to_cpu(pi->i_type.reg.row_block));
		pram_free_block(sb, blocknr);
		pram_memunlock_inode(sb, pi);
		pi->i_type.reg.row_block = 0;
		goto update_blocks;
	}
	pram_memunlock_inode(sb, pi);

 update_blocks:
	pi->i_blocks = cpu_to_be32(inode->i_blocks);
	pram_memlock_inode(sb, pi);
}

static void pram_truncate_blocks(struct inode *inode, loff_t start, loff_t end)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode)))
		return;

	__pram_truncate_blocks(inode, start, end);
	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	pram_update_inode(inode);
}

/*
 * Allocate num data blocks for inode, starting at given file-relative
 * block number.
 */
int pram_alloc_blocks(struct inode *inode, int file_blocknr, unsigned int num)
{
	struct super_block *sb = inode->i_sb;
	struct pram_inode *pi = pram_get_inode(sb, inode->i_ino);
	int N = sb->s_blocksize >> 3; /* num block ptrs per block */
	int Nbits = sb->s_blocksize_bits - 3;
	int first_file_blocknr;
	int last_file_blocknr;
	int first_row_index, last_row_index;
	int i, j, errval;
	unsigned long blocknr;
	u64 *row;
	u64 *col;

	if (!pi->i_type.reg.row_block) {
		/* alloc the 2nd order array block */
		errval = pram_new_block(sb, &blocknr, 1);
		if (errval) {
			pram_dbg("failed to alloc 2nd order array block\n");
			goto fail;
		}
		pram_memunlock_inode(sb, pi);
		pi->i_type.reg.row_block = cpu_to_be64(pram_get_block_off(sb,
								      blocknr));
		pram_memlock_inode(sb, pi);
	}

	row = pram_get_block(sb, be64_to_cpu(pi->i_type.reg.row_block));

	first_file_blocknr = file_blocknr;
	last_file_blocknr = file_blocknr + num - 1;

	first_row_index = first_file_blocknr >> Nbits;
	last_row_index  = last_file_blocknr >> Nbits;

	for (i = first_row_index; i <= last_row_index; i++) {
		int first_col_index, last_col_index;

		/*
		 * we are starting a new row, so make sure
		 * there is a block allocated for the row.
		 */
		if (!row[i]) {
			/* allocate the row block */
			errval = pram_new_block(sb, &blocknr, 1);
			if (errval) {
				pram_dbg("failed to alloc row block\n");
				goto fail;
			}
			pram_memunlock_block(sb, row);
			row[i] = cpu_to_be64(pram_get_block_off(sb, blocknr));
			pram_memlock_block(sb, row);
		}
		col = pram_get_block(sb, be64_to_cpu(row[i]));

		first_col_index = (i == first_row_index) ?
			first_file_blocknr & (N-1) : 0;

		last_col_index = (i == last_row_index) ?
			last_file_blocknr & (N-1) : N-1;

		for (j = first_col_index; j <= last_col_index; j++) {
			if (!col[j]) {
				errval = pram_new_data_block(inode, &blocknr,
							     1);
				if (errval) {
					pram_dbg("fail to alloc data block\n");
					if (j != first_col_index) {
						__pram_truncate_blocks(inode,
							inode->i_size,
					inode->i_size + ((j - first_col_index)
					<< inode->i_sb->s_blocksize_bits));
					}
					goto fail;
				}
				pram_memunlock_block(sb, col);
				col[j] = cpu_to_be64(pram_get_block_off(sb,
								      blocknr));
				pram_memlock_block(sb, col);
			}
		}
	}

	errval = 0;
 fail:
	return errval;
}

static int pram_read_inode(struct inode *inode, struct pram_inode *pi)
{
	int ret = -EIO;

	mutex_lock(&PRAM_I(inode)->i_meta_mutex);

	if (pram_calc_checksum((u8 *)pi, PRAM_INODE_SIZE)) {
		pram_err(inode->i_sb, "checksum error in inode %08x\n",
			  (u32)inode->i_ino);
		goto bad_inode;
	}

	inode->i_mode = be16_to_cpu(pi->i_mode);
	i_uid_write(inode, be32_to_cpu(pi->i_uid));
	i_gid_write(inode, be32_to_cpu(pi->i_gid));
	set_nlink(inode, be16_to_cpu(pi->i_links_count));
	inode->i_size = be32_to_cpu(pi->i_size);
	inode->i_atime.tv_sec = be32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = be32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = be32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
		inode->i_ctime.tv_nsec = 0;
	inode->i_generation = be32_to_cpu(pi->i_generation);
	pram_set_inode_flags(inode, pi);

	/* check if the inode is active. */
	if (inode->i_nlink == 0 && (inode->i_mode == 0 ||
				    be32_to_cpu(pi->i_dtime))) {
		/* this inode is deleted */
		pram_dbg("read inode: inode %lu not active", inode->i_ino);
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = be32_to_cpu(pi->i_blocks);
	inode->i_ino = pram_get_inodenr(inode->i_sb, pi);
	inode->i_mapping->a_ops = &pram_aops;
	inode->i_mapping->backing_dev_info = &pram_backing_dev_info;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		if (pram_use_xip(inode->i_sb)) {
			inode->i_mapping->a_ops = &pram_aops_xip;
			inode->i_fop = &pram_xip_file_operations;
		} else {
			inode->i_op = &pram_file_inode_operations;
			inode->i_fop = &pram_file_operations;
		}
		break;
	case S_IFDIR:
		inode->i_op = &pram_dir_inode_operations;
		inode->i_fop = &pram_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &pram_symlink_inode_operations;
		break;
	default:
		inode->i_size = 0;
		inode->i_op = &pram_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   be32_to_cpu(pi->i_type.dev.rdev));
		break;
	}

	mutex_unlock(&PRAM_I(inode)->i_meta_mutex);
	return 0;

 bad_inode:
	mutex_unlock(&PRAM_I(inode)->i_meta_mutex);
	return ret;
}

int pram_update_inode(struct inode *inode)
{
	struct pram_inode *pi;
	int retval = 0;

	pi = pram_get_inode(inode->i_sb, inode->i_ino);
	if (!pi)
		return -EACCES;

	mutex_lock(&PRAM_I(inode)->i_meta_mutex);

	pram_memunlock_inode(inode->i_sb, pi);
	pi->i_mode = cpu_to_be16(inode->i_mode);
	pi->i_uid = cpu_to_be32(i_uid_read(inode));
	pi->i_gid = cpu_to_be32(i_gid_read(inode));
	pi->i_links_count = cpu_to_be16(inode->i_nlink);
	pi->i_size = cpu_to_be32(inode->i_size);
	pi->i_blocks = cpu_to_be32(inode->i_blocks);
	pi->i_atime = cpu_to_be32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_be32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_be32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_be32(inode->i_generation);
	pram_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->i_type.dev.rdev = cpu_to_be32(inode->i_rdev);

	pram_memlock_inode(inode->i_sb, pi);

	mutex_unlock(&PRAM_I(inode)->i_meta_mutex);
	return retval;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
static void pram_free_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct pram_super_block *ps;
	struct pram_inode *pi;
	unsigned long inode_nr;

	pram_xattr_delete_inode(inode);

	mutex_lock(&PRAM_SB(sb)->s_lock);

	inode_nr = (inode->i_ino - PRAM_ROOT_INO) >> PRAM_INODE_BITS;

	pi = pram_get_inode(sb, inode->i_ino);
	pram_memunlock_inode(sb, pi);
	pi->i_dtime = cpu_to_be32(get_seconds());
	pi->i_type.reg.row_block = 0;
	pi->i_xattr = 0;
	pram_memlock_inode(sb, pi);

	/* increment s_free_inodes_count */
	ps = pram_get_super(sb);
	pram_memunlock_super(sb, ps);
	if (inode_nr < be32_to_cpu(ps->s_free_inode_hint))
		ps->s_free_inode_hint = cpu_to_be32(inode_nr);
	be32_add_cpu(&ps->s_free_inodes_count, 1);
	if (be32_to_cpu(ps->s_free_inodes_count) ==
					 be32_to_cpu(ps->s_inodes_count) - 1) {
		/* filesystem is empty */
		pram_dbg("fs is empty!\n");
		ps->s_free_inode_hint = cpu_to_be32(1);
	}
	pram_memlock_super(sb, ps);

	mutex_unlock(&PRAM_SB(sb)->s_lock);
}

struct inode *pram_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct pram_inode *pi;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	pi = pram_get_inode(sb, ino);
	if (!pi) {
		err = -EACCES;
		goto fail;
	}
	err = pram_read_inode(inode, pi);
	if (unlikely(err))
		goto fail;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

void pram_evict_inode(struct inode *inode)
{
	int want_delete = 0;

	if (!inode->i_nlink && !is_bad_inode(inode))
		want_delete = 1;

	truncate_inode_pages(&inode->i_data, 0);

	if (want_delete) {
		sb_start_intwrite(inode->i_sb);
		/* unlink from chain in the inode's directory */
		pram_remove_link(inode);
		pram_truncate_blocks(inode, 0, inode->i_size);
		inode->i_size = 0;
	}

	clear_inode(inode);

	if (want_delete) {
		pram_free_inode(inode);
		sb_end_intwrite(inode->i_sb);
	}
}


struct inode *pram_new_inode(struct inode *dir, umode_t mode,
			     const struct qstr *qstr)
{
	struct super_block *sb;
	struct pram_sb_info *sbi;
	struct pram_super_block *ps;
	struct inode *inode;
	struct pram_inode *pi = NULL;
	struct pram_inode *diri = NULL;
	int i, errval;
	ino_t ino = 0;

	sb = dir->i_sb;
	sbi = (struct pram_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&PRAM_SB(sb)->s_lock);
	ps = pram_get_super(sb);

	if (ps->s_free_inodes_count) {
		/* find the oldest unused pram inode */
		for (i = be32_to_cpu(ps->s_free_inode_hint);
		     i < be32_to_cpu(ps->s_inodes_count); i++) {
			ino = PRAM_ROOT_INO + (i << PRAM_INODE_BITS);
			pi = pram_get_inode(sb, ino);
			/* check if the inode is active. */
			if (be16_to_cpu(pi->i_links_count) == 0 &&
			   (be16_to_cpu(pi->i_mode) == 0 ||
			   be32_to_cpu(pi->i_dtime))) {
				/* this inode is deleted */
				break;
			}
		}

		if (unlikely(i >= be32_to_cpu(ps->s_inodes_count))) {
			pram_err(sb, "free inodes count!=0 but none free!?\n");
			errval = -ENOSPC;
			goto fail1;
		}

		pram_dbg("allocating inode %lu\n", ino);
	} else {
		pram_dbg("no space left to create new inode!\n");
		errval = -ENOSPC;
		goto fail1;
	}

	diri = pram_get_inode(sb, dir->i_ino);
	if (!diri) {
		errval = -EACCES;
		goto fail1;
	}

	/* chosen inode is in ino */
	inode->i_ino = ino;
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);

	pram_memunlock_inode(sb, pi);
	pi->i_d.d_next = 0;
	pi->i_d.d_prev = 0;
	pi->i_dtime = 0;
	pi->i_flags = pram_mask_flags(mode, diri->i_flags);
	pram_memlock_inode(sb, pi);

	pram_set_inode_flags(inode, pi);

	if (insert_inode_locked(inode) < 0) {
		errval = -EINVAL;
		goto fail1;
	}
	errval = pram_write_inode(inode, NULL);
	if (errval)
		goto fail2;

	errval = pram_init_acl(inode, dir);
	if (errval)
		goto fail2;

	errval = pram_init_security(inode, dir, qstr);
	if (errval)
		goto fail2;

	pram_memunlock_super(sb, ps);
	be32_add_cpu(&ps->s_free_inodes_count, -1);
	if (i < be32_to_cpu(ps->s_inodes_count)-1)
		ps->s_free_inode_hint = cpu_to_be32(i+1);
	else
		ps->s_free_inode_hint = 0;
	pram_memlock_super(sb, ps);

	mutex_unlock(&PRAM_SB(sb)->s_lock);

	return inode;
fail2:
	mutex_unlock(&PRAM_SB(sb)->s_lock);
	clear_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(errval);
fail1:
	mutex_unlock(&PRAM_SB(sb)->s_lock);
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(errval);
}

int pram_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return pram_update_inode(inode);
}

/*
 * dirty_inode() is called from __mark_inode_dirty()
 */
void pram_dirty_inode(struct inode *inode, int flags)
{
	pram_update_inode(inode);
}

static int pram_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	loff_t offset, size;
	unsigned long fillsize, blocknr, bytes_filled;
	u64 block;
	void *buf, *bp;
	int ret;

	buf = kmap(page);
	if (!buf)
		return -ENOMEM;

	offset = page_offset(page);
	size = i_size_read(inode);
	blocknr = page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	fillsize = 0;
	bytes_filled = 0;
	ret = 0;
	if (offset < size) {
		size -= offset;
		fillsize = size > PAGE_SIZE ? PAGE_SIZE : size;
		while (fillsize) {
			int count = fillsize > sb->s_blocksize ?
						sb->s_blocksize : fillsize;
			block = pram_find_data_block(inode, blocknr);
			if (likely(block)) {
				bp = pram_get_block(sb, block);
				if (!bp) {
					SetPageError(page);
					bytes_filled = 0;
					ret = -EIO;
					goto out;
				}
				memcpy(buf + bytes_filled, bp, count);
			} else {
				memset(buf + bytes_filled, 0, count);
			}
			bytes_filled += count;
			fillsize -= count;
			blocknr++;
		}
	}
 out:
	if (bytes_filled < PAGE_SIZE)
		memset(buf + bytes_filled, 0, PAGE_SIZE - bytes_filled);
	if (ret == 0)
		SetPageUptodate(page);

	flush_dcache_page(page);
	kunmap(page);
	unlock_page(page);
	return ret;
}

/*
 * Called to zeros out a single block. It's used in the "resize"
 * to avoid to keep data in case the file grow up again.
 */
static int pram_block_truncate_page(struct inode *inode, loff_t newsize)
{
	struct super_block *sb = inode->i_sb;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long blocknr, length;
	u64 blockoff;
	char *bp;
	int ret = 0;

	/* Block boundary or extending ? */
	if (!offset || newsize > inode->i_size)
		goto out;

	length = sb->s_blocksize - offset;
	blocknr = newsize >> sb->s_blocksize_bits;

	blockoff = pram_find_data_block(inode, blocknr);

	/* Hole ? */
	if (!blockoff)
		goto out;

	bp = pram_get_block(inode->i_sb, blockoff);
	if (!bp) {
		ret = -EACCES;
		goto out;
	}
	pram_memunlock_block(sb, bp);
	memset(bp + offset, 0, length);
	pram_memlock_block(sb, bp);
out:
	return ret;
}

static int pram_setsize(struct inode *inode, loff_t newsize)
{
	int ret = 0;
	loff_t oldsize = inode->i_size;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode)))
		return -EINVAL;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	if (newsize != oldsize) {
		if (mapping_is_xip(inode->i_mapping))
			ret = xip_truncate_page(inode->i_mapping, newsize);
		else
			ret = pram_block_truncate_page(inode, newsize);

		if (ret)
			return ret;
		i_size_write(inode, newsize);
	}
	/*
	 * Wait for any concurrent readers to finish before to truncate the
	 * blocks. Any new reader will see the new i_size so no problem.
	 * In addition we have to wait, in xip case, the call of xip_file_fault.
	 */
	synchronize_rcu();
	truncate_pagecache(inode, oldsize, newsize);
	__pram_truncate_blocks(inode, newsize, oldsize);
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(inode, newsize);
	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	pram_update_inode(inode);

	return ret;
}

int pram_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct pram_inode *pi = pram_get_inode(inode->i_sb, inode->i_ino);
	int error;

	if (!pi)
		return -EACCES;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if (attr->ia_valid & ATTR_SIZE &&
	    (attr->ia_size != inode->i_size ||
	    pi->i_flags & cpu_to_be32(PRAM_EOFBLOCKS_FL))) {
		error = pram_setsize(inode, attr->ia_size);
		if (error)
			return error;
	}
	setattr_copy(inode, attr);
	if (attr->ia_valid & ATTR_MODE)
		error = pram_acl_chmod(inode);
	error = pram_update_inode(inode);

	return error;
}

void pram_set_inode_flags(struct inode *inode, struct pram_inode *pi)
{
	unsigned int flags = be32_to_cpu(pi->i_flags);

	inode->i_flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
}

void pram_get_inode_flags(struct inode *inode, struct pram_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int pram_flags = be32_to_cpu(pi->i_flags);

	pram_flags &= ~(FS_SYNC_FL|FS_APPEND_FL|FS_IMMUTABLE_FL|
			FS_NOATIME_FL|FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		pram_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		pram_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		pram_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		pram_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		pram_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_be32(pram_flags);
}

const struct address_space_operations pram_aops = {
	.readpage	= pram_readpage,
	.direct_IO	= pram_direct_IO,
};

const struct address_space_operations pram_aops_xip = {
	.get_xip_mem	= pram_get_xip_mem,
};
