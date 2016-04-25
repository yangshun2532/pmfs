/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "pmfs.h"

/*
 *	Parent is locked.
 */

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

/*By ys, dir_index-relating data structures
*/
#ifdef DX_DEBUG
#define dxtrace(command) command
#else
#define dxtrace(command)
#endif

struct dx_root
{
	struct fake_dirent dot;
	char dot_name[4];
	struct fake_dirent dotdot;
	char dotdot_name[4];
	struct dx_root_info
	{
		__le32 reserved_zero;
		u8 hash_version;
		u8 info_length; /* 8 */
		u8 indirect_levels;
		u8 unused_flags;
	}
	info;
	struct dx_entry	entries[0];
};


struct dx_frame
{
	char *bh;  //the address of a data block
	struct dx_entry *entries;
	struct dx_entry *at;
};

struct fake_dirent
{
	__le32 inode;
	__le16 de_len;   // like pmfs_direntry
	u8 name_len;
	u8 file_type;
};

struct dx_countlimit
{
	__le16 limit;
	__le16 count;
};

struct dx_entry
{
	__le32 hash;
	__le32 block;
};

struct dx_node
{
	struct fake_dirent fake;
	struct dx_entry	entries[0];
};

struct dx_map_entry
{
	u32 hash;
	u16 offs;
	u16 size;
};


static inline unsigned dx_get_block (struct dx_entry *entry)
{
	return le32_to_cpu(entry->block) & 0x00ffffff;
}

static inline void dx_set_block (struct dx_entry *entry, unsigned value)
{
	entry->block = cpu_to_le32(value);
}

static inline unsigned dx_get_hash (struct dx_entry *entry)
{
	return le32_to_cpu(entry->hash);
}

static inline void dx_set_hash (struct dx_entry *entry, unsigned value)
{
	entry->hash = cpu_to_le32(value);
}

static inline unsigned dx_get_count (struct dx_entry *entries)
{
	return le16_to_cpu(((struct dx_countlimit *) entries)->count);
}

static inline unsigned dx_get_limit (struct dx_entry *entries)
{
	return le16_to_cpu(((struct dx_countlimit *) entries)->limit);
}

static inline void dx_set_count (struct dx_entry *entries, unsigned value)
{
	((struct dx_countlimit *) entries)->count = cpu_to_le16(value);
}

static inline void dx_set_limit (struct dx_entry *entries, unsigned value)
{
	((struct dx_countlimit *) entries)->limit = cpu_to_le16(value);
}

static inline unsigned dx_root_limit (struct inode *dir, unsigned infosize)
{
	unsigned entry_space = dir->i_sb->s_blocksize - PMFS_DIR_REC_LEN(1) -
		PMFS_DIR_REC_LEN(2) - infosize;
	return entry_space / sizeof(struct dx_entry);
}

static inline unsigned dx_node_limit (struct inode *dir)
{
	unsigned entry_space = dir->i_sb->s_blocksize - PMFS_DIR_REC_LEN(0);
	return entry_space / sizeof(struct dx_entry);
}

#ifdef DX_DEBUG
static void dx_show_index (char * label, struct dx_entry *entries)
{
        int i, n = dx_get_count (entries);
        printk("%s index ", label);
        for (i = 0; i < n; i++)
        {
                printk("%x->%u ", i? dx_get_hash(entries + i): 0, dx_get_block(entries + i));
        }
        printk("\n");
}
struct stats
{
	unsigned names;
	unsigned space;
	unsigned bcount;
};

static struct stats dx_show_leaf(struct dx_hash_info *hinfo, struct pmfs_direntry *de,
				 int size, int show_names)
{
	unsigned names = 0, space = 0;
	char *base = (char *) de;
	struct dx_hash_info h = *hinfo;

	printk("names: ");
	while ((char *) de < base + size)
	{
		if (de->inode)
		{
			if (show_names)
			{
				int len = de->name_len;
				char *name = de->name;
				while (len--) printk("%c", *name++);
				pmfs_dirhash(de->name, de->name_len, &h);
				printk(":%x.%u ", h.hash,
				       (unsigned) ((char *) de - base));
			}
			space += PMFS_DIR_REC_LEN(de->name_len);
			names++;
		}
		de = pmfs_next_entry(de);
	}
	printk("(%i)\n", names);
	return (struct stats) { names, space, 1 };
}

struct stats dx_show_entries(struct dx_hash_info *hinfo, struct inode *dir,
			     struct dx_entry *entries, int levels)
{
	unsigned blocksize = dir->i_sb->s_blocksize;
	struct super_block * sb = dir->i_sb;
	unsigned count = dx_get_count (entries), names = 0, space = 0, i;
	unsigned bcount = 0;
	char *blk_base;
	int err;
	printk("%i indexed blocks...\n", count);
	for (i = 0; i < count; i++, entries++)
	{
		u32 block = dx_get_block(entries), hash = i? dx_get_hash(entries): 0;
		u32 range = i < count - 1? (dx_get_hash(entries + 1) - hash): ~hash;
		struct stats stats;
		printk("%s%3u:%03u hash %8x/%8x ",levels?"":"   ", i, block, hash, range);
		if (!(blk_base = pmfs_get_block(sb, block);)) continue;
		stats = levels?
		   dx_show_entries(hinfo, dir, ((struct dx_node *) blk_base)->entries, levels - 1):
		   dx_show_leaf(hinfo, (struct pmfs_direntry *) blk_base, blocksize, 0);
		names += stats.names;
		space += stats.space;
		bcount += stats.bcount;
	}
	if (bcount)
		printk("%snames %u, fullness %u (%u%%)\n", levels?"":"   ",
			names, space/bcount,(space/bcount)*100/blocksize);
	return (struct stats) { names, space, bcount};
}
#endif

/*
 * Directory block splitting, compacting
 */

/*
 * Create map of hash values, offsets, and sizes, stored at end of block.
 * Returns number of entries mapped.
 */
static int dx_make_map(struct pmfs_direntry *de, unsigned blocksize,
		struct dx_hash_info *hinfo, struct dx_map_entry *map_tail)
{
	int count = 0;
	char *base = (char *) de;
	struct dx_hash_info h = *hinfo;

	while ((char *) de < base + blocksize)
	{
		if (de->name_len && de->inode) {
			pmfs_dirhash(de->name, de->name_len, &h);
			map_tail--;
			map_tail->hash = h.hash;
			map_tail->offs = (u16) ((char *) de - base);
			map_tail->size = le16_to_cpu(de->de_len);
			count++;
			cond_resched();
		}
		/* XXX: do we need to check de_len == 0 case? -Chris */
		de = pmfs_next_entry(de);
	}
	return count;
}

/* Sort map by hash value */
static void dx_sort_map (struct dx_map_entry *map, unsigned count)
{
        struct dx_map_entry *p, *q, *top = map + count - 1;
        int more;
        /* Combsort until bubble sort doesn't suck */
        while (count > 2)
	{
                count = count*10/13;
                if (count - 9 < 2) /* 9, 10 -> 11 */
                        count = 11;
                for (p = top, q = p - count; q >= map; p--, q--)
                        if (p->hash < q->hash)
                                swap(*p, *q);
        }
        /* Garden variety bubble sort */
        do {
                more = 0;
                q = top;
                while (q-- > map)
		{
                        if (q[1].hash >= q[0].hash)
				continue;
                        swap(*(q+1), *q);
                        more = 1;
		}
	} while(more);
}
/*
 * Move count entries from end of map between two memory locations.
 * Returns pointer to last entry moved.
 */
static struct pmfs_direntry*
dx_move_dirents(char *from, char *to, struct dx_map_entry *map, int count)
{
	unsigned de_len = 0;

	while (count--) {
		struct pmfs_direntry *de = (struct pmfs_direntry *) (from + map->offs);
		de_len = PMFS_DIR_REC_LEN(de->name_len);
		memcpy (to, de, de_len);
		((struct pmfs_direntry *) to)->de_len =
				cpu_to_le16(de_len);
		de->inode = 0;
		map++;
		to += de_len;
	}
	return (struct pmfs_direntry *) (to - de_len);
}

/*
 * Compact each dir entry in the range to the minimal de_len.
 * Returns pointer to last entry in range.
 */
static struct pmfs_direntry *dx_pack_dirents(char *base, unsigned blocksize)
{
	struct pmfs_direntry *next, *to, *prev;
	struct pmfs_direntry *de = (struct pmfs_direntry *)base;
	unsigned de_len = 0;

	prev = to = de;
	while ((char *)de < base + blocksize) {
		next = pmfs_next_entry(de);
		if (de->inode && de->name_len) {
			de_len = PMFS_DIR_REC_LEN(de->name_len);
			if (de > to)
				memmove(to, de, de_len);
			to->de_len = cpu_to_le16(de_len);
			prev = to;
			to = (struct pmfs_direntry *) (((char *) to) + de_len);
		}
		de = next;
	}
	return prev;
}

static void dx_insert_block(struct dx_frame *frame, u32 hash, u32 block)
{
	struct dx_entry *entries = frame->entries;
	struct dx_entry *old = frame->at, *new = old + 1;
	int count = dx_get_count(entries);

	assert(count < dx_get_limit(entries));
	assert(old < entries + count);
	memmove(new + 1, new, (char *)(entries + count) - (char *)(new));
	dx_set_hash(new, hash);
	dx_set_block(new, block);
	dx_set_count(entries, count + 1);
}

 static void dx_release (struct dx_frame *frames)
 {
	 if (frames[0].bh == NULL)
		 return;
 
	 if (((struct dx_root *) frames[0].bh->b_data)->info.indirect_levels)
		 brelse(frames[1].bh);
	 brelse(frames[0].bh);
 }


 /*
  * This converts a one block unindexed directory to a 3 block indexed
  * directory, and adds the dentry to the indexed directory.
  */
 static int make_indexed_dir(pmfs_transaction_t trans, struct dentry *dentry,
				 struct inode *inode, struct char *blk_base)
 {
	 struct inode	 *dir = dentry->d_parent->d_inode;
	 const char  *name = dentry->d_name.name;
	 int	 namelen = dentry->d_name.len;
	 struct char *blk_base2;
	 struct dx_root  *root;
	 struct dx_frame frames[2], *frame;
	 struct dx_entry *entries;
	 struct pmfs_direntry *de, *de2;
	 char		 *data1, *top;
	 unsigned	 len;
	 int	 retval;
	 unsigned	 blocksize;
	 struct dx_hash_info hinfo;
	 u32	 block,blocks;
	 struct fake_dirent *fde;
	 pmfs_inode* pidir;
 
	 blocksize =  dir->i_sb->s_blocksize;
	 dxtrace(printk(KERN_DEBUG "Creating index: inode %lu\n", dir->i_ino));
	 
	
	 root = (struct dx_root *)blk_base;
 
	 /* The 0th block becomes the root, move the dirents out */
	 fde = &root->dotdot;
	 de = (struct pmfs_direntry *)((char *)fde +
			 le16_to_cpu(fde->de_len));
	 if ((char *) de >= (((char *) root) + blocksize)) {
		 pmfs_error(dir->i_sb, __func__,
				"invalid de_len for '..' in inode %lu",
				dir->i_ino);
		 return -EIO;
	 }
	 len = ((char *) root) + blocksize - (char *) de;

 
	/* bh2 = ext3_append (handle, dir, &block, &retval);
	 if (!(bh2)) {
		 brelse(bh);
		 return retval;
	 }*/
	 retval = pmfs_alloc_blocks(trans, dir, 1, 1, false);
	 if (retval)
	 	return retval;
	 
	 dir->i_size += dir->i_sb->s_blocksize;
	 pidir = pmfs_get_inode(sb, dir->i_ino);
	 pmfs_update_isize(dir,pidir);
		 
	 blk_base2 = pmfs_get_block(sb, pmfs_find_data_block(dir, 1));
		 if (!blk_base2) {
			 retval = -ENOSPC;
			 return retval;
		 }
	
	 //EXT3_I(dir)->i_flags |= EXT3_INDEX_FL;
	 data1 = blk_base2;
	 
 	 pmfs_memunlock_block(sb, blk_base2);
	 memcpy (data1, de, len);
	 de = (struct pmfs_direntry*) data1;
	 top = data1 + len;
	 while ((char *)(de2 = pmfs_direntry(de)) < top)
		 de = de2;
	 de->de_len = cpu_to_le16(data1 + blocksize - (char *) de);
	 pmfs_memlock_block(sb, blk_base2);
	 
	 /* Initialize the root; the dot dirents already exist */
	 de = (struct pmfs_direntry *) (&root->dotdot);

	 pmfs_memunlock_block(sb, blk_base);
	 de->de_len = cpu_to_le16(blocksize - PMFS_DIR_REC_LEN(2));
	 memset (&root->info, 0, sizeof(root->info));
	 root->info.info_length = sizeof(root->info);
	 root->info.hash_version = PMFS_SB(dir->i_sb)->s_def_hash_version;
	 entries = root->entries;
	 dx_set_block (entries, 1);
	 dx_set_count (entries, 1);
	 dx_set_limit (entries, dx_root_limit(dir, sizeof(root->info)));
	 pmfs_memlock_block(sb, blk_base);
 
	 /* Initialize as for dx_probe */
	 hinfo.hash_version = root->info.hash_version;
	 if (hinfo.hash_version <= DX_HASH_TEA)
		 hinfo.hash_version += PMFS_SB(dir->i_sb)->s_hash_unsigned;
	 hinfo.seed = PMFS_SB(dir->i_sb)->s_hash_seed;
	 pmfs_dirhash(name, namelen, &hinfo);
	 frame = frames;
	 frame->entries = entries;
	 frame->at = entries;
	 frame->bh = blk_base;
	 blk_base = blk_base2;
	 /*
	  * Mark buffers dirty here so that if do_split() fails we write a
	  * consistent set of buffers to disk.
	  */
	 de = do_split(trans, dir, &blk_base, frame, &hinfo, &retval);
	 if (!de) 
		 return retval;
	 
	 dx_release(frames);
	 pmfs_memunlock_block(sb, blk_base);
	 de->ino = 0;
	 pmfs_memlock_block(sb, blk_base);
	 return pmfs_add_dirent_to_buf(trans, dentry, inode, de, blk_base, pidir);
 }


 /* Split a full leaf block to make room for a new dir entry.
 * Allocate a new block, and move entries so that they are approx. equally full.
 * Returns pointer to de in block into which the new entry will be inserted.
 */
static struct pmfs_direntry *do_split(pmfs_transaction_t *trans, struct inode *dir,
			struct char **blk_base, struct dx_frame *frame,
			struct dx_hash_info *hinfo, int *retval)
{
	unsigned blocksize = dir->i_sb->s_blocksize;
	unsigned count, continued;
	char *blk_base2;
	u32 blocks;
	u32 hash2;
	struct dx_map_entry *map;
	char *data1 = (*blk_base), *data2;
	unsigned split, move, size;
	struct pmfs_direntry *de = NULL, *de2;
	struct pmfs_inode* pidir;
	int	err = 0, i;

	/*bh2 = ext3_append (handle, dir, &newblock, &err);
	if (!(bh2)) {
		brelse(*bh);
		*bh = NULL;
		goto errout;
	}*/
	
	blocks = dir->i_size >> sb->s_blocksize_bits;
	err = pmfs_alloc_blocks(trans, dir, blocks, 1, false);
	if (err){
		*blk_base = NULL;
		goto errout;
	}

	dir->i_size += dir->i_sb->s_blocksize;
	pidir = pmfs_get_inode(sb, dir->i_ino);
	pmfs_update_isize(dir,pidir);
	
	blk_base2 = pmfs_get_block(sb, pmfs_find_data_block(dir, blocks));
	if (!blk_base2) {
		err = -ENOSPC;
		goto errout;
	}
	
	data2 = blk_base2;

	/* create map in the end of data2 block */
	map = (struct dx_map_entry *) (data2 + blocksize);

	pmfs_memunlock_block(sb, blk_base2);
	count = dx_make_map ((struct pmfs_direntry *) data1,
			     blocksize, hinfo, map);
	map -= count;
	dx_sort_map (map, count);
	pmfs_memlock_block(sb, blk_base2);
	
	/* Split the existing block in the middle, size-wise */
	size = 0;
	move = 0;
	for (i = count-1; i >= 0; i--) {
		/* is more than half of this entry in 2nd half of the block? */
		if (size + map[i].size/2 > blocksize/2)
			break;
		size += map[i].size;
		move++;
	}
	/* map index at which we will split */
	split = count - move;
	hash2 = map[split].hash;
	continued = hash2 == map[split - 1].hash;
	dxtrace(printk("Split block %i at %x, %i/%i\n",
		dx_get_block(frame->at), hash2, split, count-split));

	/* Fancy dance to stay within two buffers */
	pmfs_memunlock_block(sb, *blk_base);
	pmfs_memunlock_block(sb, blk_base2);
	de2 = dx_move_dirents(data1, data2, map + split, count - split);
	de = dx_pack_dirents(data1,blocksize);
	de->de_len = cpu_to_le16(data1 + blocksize - (char *) de);
	de2->de_len = cpu_to_le16(data2 + blocksize - (char *) de2);
	pmfs_memlock_block(sb, blk_base2);
	pmfs_memlock_block(sb, *blk_base);
	
	dxtrace(dx_show_leaf (hinfo, (struct pmfs_direntry *) data1, blocksize, 1));
	dxtrace(dx_show_leaf (hinfo, (struct pmfs_direntry *) data2, blocksize, 1));

	/* Which block gets the new entry? */
	if (hinfo->hash >= hash2)
	{
		swap(*blk_base, blk_base2);
		de = de2;
	}
	dx_insert_block (frame, hash2 + continued,blocks);
	
	dxtrace(dx_show_index ("frame", frame->entries));
	return de;

errout:
	*retval = err;
	return NULL;
}

/*
 * Probe for a directory leaf block to search.
 *
 * dx_probe can return ERR_BAD_DX_DIR, which means there was a format
 * error in the directory index, and the caller should fall back to
 * searching the directory normally.  The callers of dx_probe **MUST**
 * check for this error code, and make sure it never gets reflected
 * back to userspace.
 */
static struct dx_frame *
dx_probe(struct qstr *entry, struct inode *dir,
	 struct dx_hash_info *hinfo, struct dx_frame *frame_in, int *retval)
{
	unsigned count, indirect;
	struct dx_entry *at, *entries, *p, *q, *m;
	struct dx_root *root;
	struct char *blk_base;
	struct dx_frame *frame = frame_in;
	u32 hash;

	frame->bh = NULL;

	blk_base = pmfs_get_block(sb, pmfs_find_data_block(dir, 0));
		if (!blk_base) {
			*retval = ERR_BAD_DX_DIR;
			goto fail;
			}
	/*if (!(bh = ext3_dir_bread(NULL, dir, 0, 0, err))) {
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}*/
	root = (struct dx_root *)blk_base;
	if (root->info.hash_version != DX_HASH_TEA &&
	    root->info.hash_version != DX_HASH_HALF_MD4 &&
	    root->info.hash_version != DX_HASH_LEGACY) {
		pmfs_warning(dir->i_sb, __func__,
			     "Unrecognised inode hash code %d",
			     root->info.hash_version);
		*retval = ERR_BAD_DX_DIR;
		goto fail;
	}
	hinfo->hash_version = root->info.hash_version;
	if (hinfo->hash_version <= DX_HASH_TEA)
		hinfo->hash_version += PMFS_SB(dir->i_sb)->s_hash_unsigned;
	hinfo->seed = PMFS_SB(dir->i_sb)->s_hash_seed;
	if (entry)
		pmfs_dirhash(entry->name, entry->len, hinfo);
	hash = hinfo->hash;

	if (root->info.unused_flags & 1) {
		pmfs_warning(dir->i_sb, __func__,
			     "Unimplemented inode hash flags: %#06x",
			     root->info.unused_flags);
		*retval = ERR_BAD_DX_DIR;
		goto fail;
	}

	if ((indirect = root->info.indirect_levels) > 1) {
		pmfs_warning(dir->i_sb, __func__,
			     "Unimplemented inode hash depth: %#06x",
			     root->info.indirect_levels);
		*retval = ERR_BAD_DX_DIR;
		goto fail;
	}

	entries = (struct dx_entry *) (((char *)&root->info) +
				       root->info.info_length);

	if (dx_get_limit(entries) != dx_root_limit(dir,
						   root->info.info_length)) {
		pmfs_warning(dir->i_sb, __func__,
			     "dx entry: limit != root limit");
		*retval = ERR_BAD_DX_DIR;
		goto fail;
	}

	dxtrace (printk("Look up %x", hash));
	while (1)
	{
		count = dx_get_count(entries);
		if (!count || count > dx_get_limit(entries)) {
			pmfs_warning(dir->i_sb, __func__,
				     "dx entry: no count or count > limit");
			*retval = ERR_BAD_DX_DIR;
			goto fail2;
		}

		p = entries + 1;
		q = entries + count - 1;
		while (p <= q)
		{
			m = p + (q - p)/2;
			dxtrace(printk("."));
			if (dx_get_hash(m) > hash)
				q = m - 1;
			else
				p = m + 1;
		}

		if (0) // linear search cross check
		{
			unsigned n = count - 1;
			at = entries;
			while (n--)
			{
				dxtrace(printk(","));
				if (dx_get_hash(++at) > hash)
				{
					at--;
					break;
				}
			}
			assert (at == p - 1);
		}

		at = p - 1;
		dxtrace(printk(" %x->%u\n", at == entries? 0: dx_get_hash(at), dx_get_block(at)));
		frame->bh = blk_base;
		frame->entries = entries;
		frame->at = at;
		if (!indirect--) return frame;

		blk_base = pmfs_get_block(sb, pmfs_find_data_block(dir, dx_get_block(frame->at)));
		if (!blk_base) {
			*retval = ERR_BAD_DX_DIR;
			goto fail2;
			}
		at = entries = ((struct dx_node *) blk_base)->entries;
		if (dx_get_limit(entries) != dx_node_limit (dir)) {
			pmfs_warning(dir->i_sb, __func__,
				     "dx entry: limit != node limit");
			
			*err = ERR_BAD_DX_DIR;
			goto fail2;
		}
		frame++;
		frame->bh = NULL;
	}
fail2:
	while (frame >= frame_in) {
		frame--;
	}
fail:
	if (*err == ERR_BAD_DX_DIR)
		pmfs_warning(dir->i_sb, __func__,
			     "Corrupt dir inode %ld, running e2fsck is "
			     "recommended.", dir->i_ino);
	return NULL;
}


/*end By ys*/


static int pmfs_add_dirent_to_buf(pmfs_transaction_t *trans,
	struct dentry *dentry, struct inode *inode,
	struct pmfs_direntry *de, u8 *blk_base,  struct pmfs_inode *pidir)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned short reclen;
	int nlen, rlen;
	char *top;

	reclen = PMFS_DIR_REC_LEN(namelen);
	if (!de) {
		de = (struct pmfs_direntry *)blk_base;
		top = blk_base + dir->i_sb->s_blocksize - reclen;
		while ((char *)de <= top) {
#if 0
			if (!pmfs_check_dir_entry("pmfs_add_dirent_to_buf",
			    dir, de, blk_base, offset))
				return -EIO;
			if (pmfs_match(namelen, name, de))
				return -EEXIST;
#endif
			rlen = le16_to_cpu(de->de_len);
			if (de->ino) {
				nlen = PMFS_DIR_REC_LEN(de->name_len);
				if ((rlen - nlen) >= reclen)
					break;
			} else if (rlen >= reclen)
				break;
			de = (struct pmfs_direntry *)((char *)de + rlen);
		}
		if ((char *)de > top)
			return -ENOSPC;
	}
	rlen = le16_to_cpu(de->de_len);

	if (de->ino) {
		struct pmfs_direntry *de1;
		pmfs_add_logentry(dir->i_sb, trans, &de->de_len,
			sizeof(de->de_len), LE_DATA);
		nlen = PMFS_DIR_REC_LEN(de->name_len);
		de1 = (struct pmfs_direntry *)((char *)de + nlen);
		pmfs_memunlock_block(dir->i_sb, blk_base);
		de1->de_len = cpu_to_le16(rlen - nlen);
		de->de_len = cpu_to_le16(nlen);
		pmfs_memlock_block(dir->i_sb, blk_base);
		de = de1;
	} else {
		pmfs_add_logentry(dir->i_sb, trans, &de->ino,
			sizeof(de->ino), LE_DATA);
	}
	pmfs_memunlock_block(dir->i_sb, blk_base);
	/*de->file_type = 0;*/
	if (inode) {
		de->ino = cpu_to_le64(inode->i_ino);
		/*de->file_type = IF2DT(inode->i_mode); */
	} else {
		de->ino = 0;
	}
	de->name_len = namelen;
	memcpy(de->name, name, namelen);
	pmfs_memlock_block(dir->i_sb, blk_base);
	pmfs_flush_buffer(de, reclen, false);
	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	/*dir->i_version++; */

	pmfs_memunlock_inode(dir->i_sb, pidir);
	pidir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	pidir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
	pmfs_memlock_inode(dir->i_sb, pidir);
	return 0;
}

/*
 * By ys
 * Returns 0 for success, or a negative error value 
 */
static int pmfs_dx_add_entry(pmfs_transaction_t *trans, struct dentry *dentry,
			     struct inode *inode)
{
	struct dx_frame frames[2], *frame;
	struct dx_entry *entries, *at;
	struct dx_hash_info hinfo;
	char *blk_base;
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block * sb = dir->i_sb;
	struct pmfs_direntry*de;
	struct pmfs_inode* pidir;
	int retval = -EINVAL;

	frame = dx_probe(&dentry->d_name, dir, &hinfo, frames, &retval);
	if (!frame)
		goto out;
	entries = frame->entries;
	at = frame->at;

	blk_base = pmfs_get_block(sb, pmfs_find_data_block(dir, dx_get_block(frame->at)));
		if (!blk_base) {
			retval = -EIO;
			goto out;
			}
	pidir = pmfs_get_inode(sb, dir->i_ino);
	retval = pmfs_add_dirent_to_buf(trans, dentry, inode,
				NULL, blk_base, pidir);
		if (retval != -ENOSPC)
			goto out;
		

	/* Block full, should compress but for now just split */
	dxtrace(printk("using %u of %u node entries\n",
		       dx_get_count(entries), dx_get_limit(entries)));
	/* Need to split index? */
	if (dx_get_count(entries) == dx_get_limit(entries)) {
		u32 blocks;
		unsigned icount = dx_get_count(entries);
		int levels = frame - frames;
		struct dx_entry *entries2;
		struct dx_node *node2;
		struct char *blk_base2;

		if (levels && (dx_get_count(frames->entries) ==
			       dx_get_limit(frames->entries))) {
			printk(KERN_WARNING
				     "Directory index full! in %s",__func__);
			err = -ENOSPC;
			goto out;
		}
		blocks = dir->i_size >> sb->s_blocksize_bits;
		retval = pmfs_alloc_blocks(trans, dir, blocks, 1, false);
		if (retval)
			goto out;

		dir->i_size += dir->i_sb->s_blocksize;
		pmfs_update_isize(dir, pidir);

		blk_base2 = pmfs_get_block(sb, pmfs_find_data_block(dir, blocks));
		if (!blk_base2) {
			retval = -ENOSPC;
			goto out;
		}
	
		node2 = (struct dx_node *)(blk_base2);
		entries2 = node2->entries;
		
		pmfs_memunlock_block(sb, blk_base2);
		memset(&node2->fake, 0, sizeof(struct fake_dirent));
		node2->fake.de_len = cpu_to_le16(sb->s_blocksize);
		pmfs_memlock_block(sb, blk_base2);
		
		if (levels) {
			unsigned icount1 = icount/2, icount2 = icount - icount1;
			unsigned hash2 = dx_get_hash(entries + icount1);
			dxtrace(printk("Split index %i/%i\n", icount1, icount2));

			pmfs_memunlock_block(sb, blk_base2);
			memcpy ((char *) entries2, (char *) (entries + icount1),
				icount2 * sizeof(struct dx_entry));
			dx_set_count (entries, icount1);
			dx_set_count (entries2, icount2);
			dx_set_limit (entries2, dx_node_limit(dir));
			pmfs_memlock_block(sb, blk_base2);
			
			/* Which index block gets the new entry? */
			if (at - entries >= icount1) {
				frame->at = at = at - entries - icount1 + entries2;
				frame->entries = entries = entries2;
				swap(frame->bh, blk_base2);
			}
			dx_insert_block (frames + 0, hash2, blocks);
			dxtrace(dx_show_index ("node", frames[1].entries));
			dxtrace(dx_show_index ("node",
			       ((struct dx_node *) blk_base)->entries));
		
		} else {
			dxtrace(printk("Creating second level index...\n"));

			pmfs_memunlock_block(sb, blk_base2);
			memcpy((char *) entries2, (char *) entries,
			       icount * sizeof(struct dx_entry));
			dx_set_limit(entries2, dx_node_limit(dir));
			pmfs_memlock_block(sb, blk_base2);

			pmfs_memunlock_block(sb, blk_base);
			/* Set up root */
			dx_set_count(entries, 1);
			dx_set_block(entries + 0, blocks);
			((struct dx_root *) frames[0].bh->b_data)->info.indirect_levels = 1;
			pmfs_memunlock_block(sb, blk_base);
			
			/* Add new access path frame */
			frame = frames + 1;
			frame->at = at = at - entries + entries2;
			frame->entries = entries = entries2;
			frame->bh = blk_base2;
		}
	}
	de = do_split(trans, dir, &blk_base, frame, &hinfo, &retval);
	pmfs_memunlock_block(sb, blk_base);
	de->ino = 0;
	pmfs_memlock_block(sb, blk_base);
	if (!de)
		goto out;
	retval = pmfs_add_dirent_to_buf(trans, dentry, inode,
				de, blk_base, pidir);
	out:
		return retval;

}


/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int pmfs_add_entry(pmfs_transaction_t *trans, struct dentry *dentry,
		struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	int retval = -EINVAL;
	unsigned long block, blocks;
	struct pmfs_direntry *de;
	char *blk_base;
	int dx_fallback = 0;
	struct pmfs_inode *pidir;

	if (!dentry->d_name.len)
		return -EINVAL;

/* By ys, add a index to the directory
*
*/
	
	pidir = pmfs_get_inode(sb, dir->i_ino);
	pmfs_add_logentry(sb, trans, pidir, MAX_DATA_PER_LENTRY, LE_DATA);

	if (test_opt(sb,DIR_INDEX)) {
			printk("go to dx_add_entry");
			retval = pmfs_dx_add_entry(trans, dentry, inode);
			if (!retval || (retval != ERR_BAD_DX_DIR))
				return retval;
			dx_fallback++;
		}


	blocks = dir->i_size >> sb->s_blocksize_bits;
	for (block = 0; block < blocks; block++) {
		blk_base =
			pmfs_get_block(sb, pmfs_find_data_block(dir, block));
		if (!blk_base) {
			retval = -EIO;
			goto out;
		}
		retval = pmfs_add_dirent_to_buf(trans, dentry, inode,
				NULL, blk_base, pidir);
		if (retval != -ENOSPC)
			goto out;
		/*By ys*/
		
		if(blocks == 1 && !dx_fallback && test_opt(sb,DIR_INDEX))
			return make_indexed_dir(trans, dentry, inode, blk_base);
		/*End ys*/
	}
	retval = pmfs_alloc_blocks(trans, dir, blocks, 1, false);
	if (retval)
		goto out;

	dir->i_size += dir->i_sb->s_blocksize;
	pmfs_update_isize(dir, pidir);

	blk_base = pmfs_get_block(sb, pmfs_find_data_block(dir, blocks));
	if (!blk_base) {
		retval = -ENOSPC;
		goto out;
	}
	/* No need to log the changes to this de because its a new block */
	de = (struct pmfs_direntry *)blk_base;
	pmfs_memunlock_block(sb, blk_base);
	de->ino = 0;
	de->de_len = cpu_to_le16(sb->s_blocksize);
	pmfs_memlock_block(sb, blk_base);
	/* Since this is a new block, no need to log changes to this block */
	retval = pmfs_add_dirent_to_buf(NULL, dentry, inode, de, blk_base,
		pidir);
out:
	return retval;
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int pmfs_remove_entry(pmfs_transaction_t *trans, struct dentry *de,
		struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct inode *dir = de->d_parent->d_inode;
	struct pmfs_inode *pidir;
	struct qstr *entry = &de->d_name;
	struct pmfs_direntry *res_entry, *prev_entry;
	int retval = -EINVAL;
	unsigned long blocks, block;
	char *blk_base = NULL;

	if (!de->d_name.len)
		return -EINVAL;

	blocks = dir->i_size >> sb->s_blocksize_bits;

//By ys
	if (test_opt(sb,DIR_INDEX)) {
			retval = pmfs_dx_find_entry_pre(dir, entry, &res_entry, &prev_entry);
			if (retval && (retval != ERR_BAD_DX_DIR)){
				goto out;
			}
			dxtrace(printk("pmfs_find_entry: dx failed, falling back\n"));
		}


	if(retval == ERR_BAD_DX_DIR){
		for (block = 0; block < blocks; block++) {
			blk_base =
				pmfs_get_block(sb, pmfs_find_data_block(dir, block));
			if (!blk_base)
				goto out;
			if (pmfs_search_dirblock(blk_base, dir, entry,
						  block << sb->s_blocksize_bits,
						  &res_entry, &prev_entry) == 1)
				break;
		}
		if (block == blocks)
			goto out;
	}
//end ys
	if (prev_entry) {
		pmfs_add_logentry(sb, trans, &prev_entry->de_len,
				sizeof(prev_entry->de_len), LE_DATA);
		pmfs_memunlock_block(sb, blk_base);
		prev_entry->de_len =
			cpu_to_le16(le16_to_cpu(prev_entry->de_len) +
				    le16_to_cpu(res_entry->de_len));
		pmfs_memlock_block(sb, blk_base);
	} else {
		pmfs_add_logentry(sb, trans, &res_entry->ino,
				sizeof(res_entry->ino), LE_DATA);
		pmfs_memunlock_block(sb, blk_base);
		res_entry->ino = 0;
		pmfs_memlock_block(sb, blk_base);
	}
	/*dir->i_version++; */
	dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;

	pidir = pmfs_get_inode(sb, dir->i_ino);
	pmfs_add_logentry(sb, trans, pidir, MAX_DATA_PER_LENTRY, LE_DATA);

	pmfs_memunlock_inode(sb, pidir);
	pidir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	pidir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
	pmfs_memlock_inode(sb, pidir);
	retval = 0;
out:
	return retval;
}

static int pmfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	char *blk_base;
	unsigned long offset;
	struct pmfs_direntry *de;
	ino_t ino;

	offset = ctx->pos & (sb->s_blocksize - 1);
	while (ctx->pos < inode->i_size) {
		unsigned long blk = ctx->pos >> sb->s_blocksize_bits;

		blk_base =
			pmfs_get_block(sb, pmfs_find_data_block(inode, blk));
		if (!blk_base) {
			pmfs_dbg("directory %lu contains a hole at offset %lld\n",
				inode->i_ino, ctx->pos);
			ctx->pos += sb->s_blocksize - offset;
			continue;
		}
#if 0
		if (file->f_version != inode->i_version) {
			for (i = 0; i < sb->s_blocksize && i < offset; ) {
				de = (struct pmfs_direntry *)(blk_base + i);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (le16_to_cpu(de->de_len) <
				    PMFS_DIR_REC_LEN(1))
					break;
				i += le16_to_cpu(de->de_len);
			}
			offset = i;
			ctx->pos =
				(ctx->pos & ~(sb->s_blocksize - 1)) | offset;
			file->f_version = inode->i_version;
		}
#endif
		while (ctx->pos < inode->i_size
		       && offset < sb->s_blocksize) {
			de = (struct pmfs_direntry *)(blk_base + offset);
			if (!pmfs_check_dir_entry("pmfs_readdir", inode, de,
						   blk_base, offset)) {
				/* On error, skip to the next block. */
				ctx->pos = ALIGN(ctx->pos, sb->s_blocksize);
				break;
			}
			offset += le16_to_cpu(de->de_len);
			if (de->ino) {
				ino = le64_to_cpu(de->ino);
				pi = pmfs_get_inode(sb, ino);
				if (!dir_emit(ctx, de->name, de->name_len,
					ino, IF2DT(le16_to_cpu(pi->i_mode))))
					return 0;
			}
			ctx->pos += le16_to_cpu(de->de_len);
		}
		offset = 0;
	}
	return 0;
}

const struct file_operations pmfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= pmfs_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = pmfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pmfs_compat_ioctl,
#endif
};
