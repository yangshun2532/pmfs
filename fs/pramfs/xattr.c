/*
 * BRIEF DESCRIPTION
 *
 * Extended attributes operations.
 *
 * Copyright 2010-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * based on fs/ext2/xattr.c with the following copyright:
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

/*
 * Extended attributes are stored in blocks allocated outside of
 * any inode. The i_xattr field is then made to point to this allocated
 * block. If all extended attributes of an inode are identical, these
 * inodes may share the same extended attribute block. Such situations
 * are automatically detected by keeping a cache of recent attribute block
 * numbers and hashes over the block's contents in memory.
 *
 *
 * Extended attribute block layout:
 *
 *   +------------------+
 *   | header           |
 *   | entry 1          | |
 *   | entry 2          | | growing downwards
 *   | entry 3          | v
 *   | four null bytes  |
 *   | . . .            |
 *   | value 1          | ^
 *   | value 3          | | growing upwards
 *   | value 2          | |
 *   +------------------+
 *
 * The block header is followed by multiple entry descriptors. These entry
 * descriptors are variable in size, and aligned to PRAM_XATTR_PAD
 * byte boundaries. The entry descriptors are sorted by attribute name,
 * so that two extended attribute blocks can be compared efficiently.
 *
 * Attribute values are aligned to the end of the block, stored in
 * no specific order. They are also padded to PRAM_XATTR_PAD byte
 * boundaries. No additional gaps are left between them.
 *
 * Locking strategy
 * ----------------
 * pi->i_xattr is protected by PRAM_I(inode)->xattr_sem.
 * EA blocks are only changed if they are exclusive to an inode, so
 * holding xattr_sem also means that nothing but the EA block's reference
 * count will change. Multiple writers to an EA block are synchronized
 * by the mutex in each block descriptor. Block descriptors are kept in a
 * red black tree and the key is the absolute block number.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mbcache.h>
#include <linux/rwsem.h>
#include <linux/security.h>
#include "pram.h"
#include "xattr.h"
#include "acl.h"
#include "desctree.h"

#define HDR(bp) ((struct pram_xattr_header *)(bp))
#define ENTRY(ptr) ((struct pram_xattr_entry *)(ptr))
#define FIRST_ENTRY(bh) ENTRY(HDR(bh)+1)
#define IS_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)
#define GET_DESC(sbi, blocknr) \
	lookup_xblock_desc(sbi, blocknr, pram_xblock_desc_cache, 1)
#define LOOKUP_DESC(sbi, blocknr) lookup_xblock_desc(sbi, blocknr, NULL, 0)

#ifdef PRAM_XATTR_DEBUG
# define ea_idebug(inode, f...) do { \
		printk(KERN_DEBUG "inode %ld: ", inode->i_ino); \
		printk(f); \
		printk("\n"); \
	} while (0)
# define ea_bdebug(blocknr, f...) do { \
		printk(KERN_DEBUG "block %lu: ", blocknr); \
		printk(f); \
		printk("\n"); \
	} while (0)
#else
# define ea_idebug(f...)
# define ea_bdebug(f...)
#endif

static int pram_xattr_set2(struct inode *, char *, struct pram_xblock_desc *,
			   struct pram_xattr_header *);

static int pram_xattr_cache_insert(struct super_block *sb,
				   unsigned long blocknr, u32 xhash);
static struct pram_xblock_desc *pram_xattr_cache_find(struct inode *,
						 struct pram_xattr_header *);
static void pram_xattr_rehash(struct pram_xattr_header *,
			      struct pram_xattr_entry *);

static struct mb_cache *pram_xattr_cache;
static struct kmem_cache *pram_xblock_desc_cache;

static const struct xattr_handler *pram_xattr_handler_map[] = {
	[PRAM_XATTR_INDEX_USER]		     = &pram_xattr_user_handler,
#ifdef CONFIG_PRAMFS_POSIX_ACL
	[PRAM_XATTR_INDEX_POSIX_ACL_ACCESS]  = &pram_xattr_acl_access_handler,
	[PRAM_XATTR_INDEX_POSIX_ACL_DEFAULT] = &pram_xattr_acl_default_handler,
#endif
	[PRAM_XATTR_INDEX_TRUSTED]	     = &pram_xattr_trusted_handler,
#ifdef CONFIG_PRAMFS_SECURITY
	[PRAM_XATTR_INDEX_SECURITY]	     = &pram_xattr_security_handler,
#endif
};

const struct xattr_handler *pram_xattr_handlers[] = {
	&pram_xattr_user_handler,
	&pram_xattr_trusted_handler,
#ifdef CONFIG_PRAMFS_POSIX_ACL
	&pram_xattr_acl_access_handler,
	&pram_xattr_acl_default_handler,
#endif
#ifdef CONFIG_PRAMFS_SECURITY
	&pram_xattr_security_handler,
#endif
	NULL
};

static void desc_put(struct super_block *sb, struct pram_xblock_desc *desc)
{
	struct pram_sb_info *sbi = PRAM_SB(sb);
	if (!put_xblock_desc(sbi, desc)) {
		/* Ok we can free the block and its descriptor */
		pram_dbg("freeing block %lu and its descriptor", desc->blocknr);
		pram_free_block(sb, desc->blocknr);
		kmem_cache_free(pram_xblock_desc_cache, desc);
	}
}

static inline const struct xattr_handler *pram_xattr_handler(int name_index)
{
	const struct xattr_handler *handler = NULL;

	if (name_index > 0 && name_index < ARRAY_SIZE(pram_xattr_handler_map))
		handler = pram_xattr_handler_map[name_index];
	return handler;
}

/*
 * pram_xattr_get()
 *
 * Copy an extended attribute into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
int pram_xattr_get(struct inode *inode, int name_index, const char *name,
	       void *buffer, size_t buffer_size)
{
	char *bp = NULL;
	struct pram_xattr_entry *entry;
	struct pram_xblock_desc *desc;
	struct pram_inode *pi;
	size_t name_len, size;
	char *end;
	int error = 0;
	unsigned long blocknr;
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);

	ea_idebug(inode, "name=%d<%s>, buffer=%p, buffer_size=%ld",
		  name_index, name, buffer, (long)buffer_size);

	pi = pram_get_inode(sb, inode->i_ino);
	if (!pi)
		return -EINVAL;
	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255)
		return -ERANGE;
	down_read(&PRAM_I(inode)->xattr_sem);
	error = -ENODATA;
	if (!pi->i_xattr)
		goto cleanup;
	ea_idebug(inode, "reading block %llu", be64_to_cpu(pi->i_xattr));
	bp = pram_get_block(sb, be64_to_cpu(pi->i_xattr));
	error = -EIO;
	if (!bp)
		goto cleanup;
	end = bp + sb->s_blocksize;
	blocknr = pram_get_blocknr(sb, be64_to_cpu(pi->i_xattr));
	ea_bdebug(blocknr, "refcount=%d", be32_to_cpu(HDR(bp)->h_refcount));
	if (HDR(bp)->h_magic != cpu_to_be32(PRAM_XATTR_MAGIC)) {
bad_block:	pram_err(sb, "inode %ld: bad block %llu", inode->i_ino,
		be64_to_cpu(pi->i_xattr));
		error = -EIO;
		goto cleanup;
	}
	/* find named attribute */
	entry = FIRST_ENTRY(bp);
	while (!IS_LAST_ENTRY(entry)) {
		struct pram_xattr_entry *next =
			PRAM_XATTR_NEXT(entry);
		if ((char *)next >= end)
			goto bad_block;
		if (name_index == entry->e_name_index &&
		    name_len == entry->e_name_len &&
		    memcmp(name, entry->e_name, name_len) == 0)
			goto found;
		entry = next;
	}

	desc = GET_DESC(sbi, blocknr);
	if (IS_ERR(desc)) {
		error = -ENOMEM;
		goto cleanup;
	}
	desc_put(sb, desc);
	if (pram_xattr_cache_insert(sb, blocknr,
					be32_to_cpu(HDR(bp)->h_hash)))
		ea_idebug(inode, "cache insert failed");
	error = -ENODATA;
	goto cleanup;
found:
	/* check the buffer size */
	if (entry->e_value_block != 0)
		goto bad_block;
	size = be32_to_cpu(entry->e_value_size);
	if (size > inode->i_sb->s_blocksize ||
	    be16_to_cpu(entry->e_value_offs) + size > inode->i_sb->s_blocksize)
		goto bad_block;

	desc = GET_DESC(sbi, blocknr);
	if (IS_ERR(desc)) {
		error = -ENOMEM;
		goto cleanup;
	}
	desc_put(sb, desc);
	if (pram_xattr_cache_insert(sb, blocknr,
					be32_to_cpu(HDR(bp)->h_hash)))
		ea_idebug(inode, "cache insert failed");
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		/* return value of attribute */
		memcpy(buffer, bp + be16_to_cpu(entry->e_value_offs),
			size);
	}
	error = size;

cleanup:
	up_read(&PRAM_I(inode)->xattr_sem);

	return error;
}

/*
 * pram_xattr_list()
 *
 * Copy a list of attribute names into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
static int pram_xattr_list(struct dentry *dentry, char *buffer,
			   size_t buffer_size)
{
	struct inode *inode = dentry->d_inode;
	char *bp = NULL;
	struct pram_xattr_entry *entry;
	struct pram_xblock_desc *desc;
	struct pram_inode *pi;
	char *end;
	size_t rest = buffer_size;
	int error = 0;
	unsigned long blocknr;
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);

	ea_idebug(inode, "buffer=%p, buffer_size=%ld",
		  buffer, (long)buffer_size);

	pi = pram_get_inode(sb, inode->i_ino);
	if (!pi)
		return error;
	down_read(&PRAM_I(inode)->xattr_sem);
	error = 0;
	if (!pi->i_xattr)
		goto cleanup;
	ea_idebug(inode, "reading block %llu", be64_to_cpu(pi->i_xattr));
	bp = pram_get_block(sb, be64_to_cpu(pi->i_xattr));
	blocknr = pram_get_blocknr(sb, be64_to_cpu(pi->i_xattr));
	error = -EIO;
	if (!bp)
		goto cleanup;
	ea_bdebug(blocknr, "refcount=%d", be32_to_cpu(HDR(bp)->h_refcount));
	end = bp + sb->s_blocksize;
	if (HDR(bp)->h_magic != cpu_to_be32(PRAM_XATTR_MAGIC)) {
bad_block:	pram_err(sb, "inode %ld: bad block %llu", inode->i_ino,
			be64_to_cpu(pi->i_xattr));
		error = -EIO;
		goto cleanup;
	}

	/* check the on-disk data structure */
	entry = FIRST_ENTRY(bp);
	while (!IS_LAST_ENTRY(entry)) {
		struct pram_xattr_entry *next = PRAM_XATTR_NEXT(entry);

		if ((char *)next >= end)
			goto bad_block;
		entry = next;
	}

	desc = GET_DESC(sbi, blocknr);
	if (IS_ERR(desc)) {
		error = -ENOMEM;
		goto cleanup;
	}
	desc_put(sb, desc);
	if (pram_xattr_cache_insert(sb, blocknr,
					be32_to_cpu(HDR(bp)->h_hash)))
			ea_idebug(inode, "cache insert failed");

	/* list the attribute names */
	for (entry = FIRST_ENTRY(bp); !IS_LAST_ENTRY(entry);
	     entry = PRAM_XATTR_NEXT(entry)) {
		const struct xattr_handler *handler =
			pram_xattr_handler(entry->e_name_index);

		if (handler) {
			size_t size = handler->list(dentry, buffer, rest,
						    entry->e_name,
						    entry->e_name_len,
						    handler->flags);
			if (buffer) {
				if (size > rest) {
					error = -ERANGE;
					goto cleanup;
				}
				buffer += size;
			}
			rest -= size;
		}
	}
	error = buffer_size - rest;  /* total size */

cleanup:
	up_read(&PRAM_I(inode)->xattr_sem);

	return error;
}

/*
 * Inode operation listxattr()
 *
 * dentry->d_inode->i_mutex: don't care
 */
ssize_t pram_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	return pram_xattr_list(dentry, buffer, size);
}

/*
 * pram_xattr_set()
 *
 * Create, replace or remove an extended attribute for this inode. Value
 * is NULL to remove an existing extended attribute, and non-NULL to
 * either replace an existing extended attribute, or create a new extended
 * attribute. The flags XATTR_REPLACE and XATTR_CREATE
 * specify that an extended attribute must exist and must not exist
 * previous to the call, respectively.
 *
 * Returns 0, or a negative error number on failure.
 */
int pram_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t value_len, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);
	struct pram_xattr_header *header = NULL;
	struct pram_xattr_entry *here, *last;
	struct pram_inode *pi;
	struct pram_xblock_desc *desc = NULL;
	size_t name_len, free, min_offs = sb->s_blocksize;
	int not_found = 1, error;
	char *end;
	char *bp = NULL;
	unsigned long blocknr = 0;

	/*
	 * header -- Points either into bp, or to a temporarily
	 *           allocated buffer.
	 * here -- The named entry found, or the place for inserting, within
	 *         the block pointed to by header.
	 * last -- Points right after the last named entry within the block
	 *         pointed to by header.
	 * min_offs -- The offset of the first value (values are aligned
	 *             towards the end of the block).
	 * end -- Points right after the block pointed to by header.
	 */

	ea_idebug(inode, "name=%d.%s, value=%p, value_len=%ld",
		  name_index, name, value, (long)value_len);

	if (value == NULL)
		value_len = 0;
	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255 || value_len > sb->s_blocksize)
		return -ERANGE;
	pi = pram_get_inode(sb, inode->i_ino);
	if (!pi)
		return -EINVAL;
	down_write(&PRAM_I(inode)->xattr_sem);
	if (pi->i_xattr) {
		/* The inode already has an extended attribute block. */
		bp = pram_get_block(sb, be64_to_cpu(pi->i_xattr));
		error = -EIO;
		if (!bp)
			goto cleanup;
		blocknr = pram_get_blocknr(sb, be64_to_cpu(pi->i_xattr));
		ea_bdebug(blocknr, "refcount=%d",
			  be32_to_cpu(HDR(bp)->h_refcount));
		header = HDR(bp);
		end = bp + sb->s_blocksize;
		if (header->h_magic != cpu_to_be32(PRAM_XATTR_MAGIC)) {
bad_block:
			pram_err(sb, "inode %ld: bad block %llu", inode->i_ino,
				   be64_to_cpu(pi->i_xattr));
			error = -EIO;
			goto cleanup;
		}
		/* Find the named attribute. */
		here = FIRST_ENTRY(bp);
		while (!IS_LAST_ENTRY(here)) {
			struct pram_xattr_entry *next = PRAM_XATTR_NEXT(here);
			if ((char *)next >= end)
				goto bad_block;
			if (!here->e_value_block && here->e_value_size) {
				size_t offs = be16_to_cpu(here->e_value_offs);
				if (offs < min_offs)
					min_offs = offs;
			}
			not_found = name_index - here->e_name_index;
			if (!not_found)
				not_found = name_len - here->e_name_len;
			if (!not_found)
				not_found = memcmp(name, here->e_name,
						   name_len);
			if (not_found <= 0)
				break;
			here = next;
		}
		last = here;
		/* We still need to compute min_offs and last. */
		while (!IS_LAST_ENTRY(last)) {
			struct pram_xattr_entry *next = PRAM_XATTR_NEXT(last);
			if ((char *)next >= end)
				goto bad_block;
			if (!last->e_value_block && last->e_value_size) {
				size_t offs = be16_to_cpu(last->e_value_offs);
				if (offs < min_offs)
					min_offs = offs;
			}
			last = next;
		}

		/* Check whether we have enough space left. */
		free = min_offs - ((char *)last - (char *)header) -
								sizeof(__u32);
	} else {
		/* We will use a new extended attribute block. */
		free = sb->s_blocksize -
			sizeof(struct pram_xattr_header) - sizeof(__u32);
		here = last = NULL;  /* avoid gcc uninitialized warning. */
	}

	if (not_found) {
		/* Request to remove a nonexistent attribute? */
		error = -ENODATA;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		error = 0;
		if (value == NULL)
			goto cleanup;
	} else {
		/* Request to create an existing attribute? */
		error = -EEXIST;
		if (flags & XATTR_CREATE)
			goto cleanup;
		if (!here->e_value_block && here->e_value_size) {
			size_t size = be32_to_cpu(here->e_value_size);

			if (be16_to_cpu(here->e_value_offs) + size >
			    sb->s_blocksize || size > sb->s_blocksize)
				goto bad_block;
			free += PRAM_XATTR_SIZE(size);
		}
		free += PRAM_XATTR_LEN(name_len);
	}
	error = -ENOSPC;
	if (free < PRAM_XATTR_LEN(name_len) + PRAM_XATTR_SIZE(value_len))
		goto cleanup;

	/* Here we know that we can set the new attribute. */

	if (header) {
		struct mb_cache_entry *ce;

		desc = GET_DESC(sbi, blocknr);
		if (IS_ERR(desc)) {
			error = -ENOMEM;
			goto cleanup;
		}

		/* assert(header == HDR(bp)); */
		ce = mb_cache_entry_get(pram_xattr_cache,
					(struct block_device *)sbi,
					blocknr);
		mutex_lock(&desc->lock);
		pram_memunlock_block(sb, bp);
		if (header->h_refcount == cpu_to_be32(1)) {
			ea_bdebug(blocknr, "modifying in-place");
			if (ce)
				mb_cache_entry_free(ce);
			/* keep it locked while modifying it. */
		} else {
			int offset;

			if (ce)
				mb_cache_entry_release(ce);
			pram_memlock_block(sb, bp);
			mutex_unlock(&desc->lock);
			ea_bdebug(desc->blocknr, "cloning");
			header = kmalloc(inode->i_sb->s_blocksize, GFP_KERNEL);
			error = -ENOMEM;
			if (header == NULL)
				goto cleanup;
			memcpy(header, HDR(bp), inode->i_sb->s_blocksize);
			header->h_refcount = cpu_to_be32(1);

			offset = (char *)here - bp;
			here = ENTRY((char *)header + offset);
			offset = (char *)last - bp;
			last = ENTRY((char *)header + offset);
		}
	} else {
		/* Allocate a buffer where we construct the new block. */
		header = kzalloc(sb->s_blocksize, GFP_KERNEL);
		error = -ENOMEM;
		if (header == NULL)
			goto cleanup;
		end = (char *)header + sb->s_blocksize;
		header->h_magic = cpu_to_be32(PRAM_XATTR_MAGIC);
		header->h_refcount = cpu_to_be32(1);
		last = here = ENTRY(header+1);
	}

	/* Iff we are modifying the block in-place, the block is locked here. */

	if (not_found) {
		/* Insert the new name. */
		size_t size = PRAM_XATTR_LEN(name_len);
		size_t rest = (char *)last - (char *)here;
		memmove((char *)here + size, here, rest);
		memset(here, 0, size);
		here->e_name_index = name_index;
		here->e_name_len = name_len;
		memcpy(here->e_name, name, name_len);
	} else {
		if (!here->e_value_block && here->e_value_size) {
			char *first_val = (char *)header + min_offs;
			size_t offs = be16_to_cpu(here->e_value_offs);
			char *val = (char *)header + offs;
			size_t size = PRAM_XATTR_SIZE(
				be32_to_cpu(here->e_value_size));

			if (size == PRAM_XATTR_SIZE(value_len)) {
				/* The old and the new value have the same
				   size. Just replace. */
				here->e_value_size = cpu_to_be32(value_len);
				memset(val + size - PRAM_XATTR_PAD, 0,
				       PRAM_XATTR_PAD); /* Clear pad bytes. */
				memcpy(val, value, value_len);
				goto skip_replace;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = ENTRY(header+1);
			while (!IS_LAST_ENTRY(last)) {
				size_t o = be16_to_cpu(last->e_value_offs);
				if (!last->e_value_block && o < offs)
					last->e_value_offs =
						cpu_to_be16(o + size);
				last = PRAM_XATTR_NEXT(last);
			}
		}
		if (value == NULL) {
			/* Remove the old name. */
			size_t size = PRAM_XATTR_LEN(name_len);
			last = ENTRY((char *)last - size);
			memmove(here, (char *)here + size,
				(char *)last - (char *)here);
			memset(last, 0, size);
		}
	}

	if (value != NULL) {
		/* Insert the new value. */
		here->e_value_size = cpu_to_be32(value_len);
		if (value_len) {
			size_t size = PRAM_XATTR_SIZE(value_len);
			char *val = (char *)header + min_offs - size;
			here->e_value_offs =
				cpu_to_be16((char *)val - (char *)header);
			memset(val + size - PRAM_XATTR_PAD, 0,
			       PRAM_XATTR_PAD); /* Clear the pad bytes. */
			memcpy(val, value, value_len);
		}
	}

skip_replace:
	if (IS_LAST_ENTRY(ENTRY(header+1))) {
		/* This block is now empty. */
		if (bp && header == HDR(bp)) {
			/* we were modifying in-place. */
			pram_memlock_block(sb, bp);
			mutex_unlock(&desc->lock);
		}
		error = pram_xattr_set2(inode, bp, desc, NULL);
	} else {
		pram_xattr_rehash(header, here);
		if (bp && header == HDR(bp)) {
			/* we were modifying in-place. */
			pram_memlock_block(sb, bp);
			mutex_unlock(&desc->lock);
		}
		error = pram_xattr_set2(inode, bp, desc, header);
	}

cleanup:
	desc_put(sb, desc);
	if (!(bp && header == HDR(bp)))
		kfree(header);
	up_write(&PRAM_I(inode)->xattr_sem);

	return error;
}

/*
 * Second half of pram_xattr_set(): Update the file system.
 */
static int pram_xattr_set2(struct inode *inode, char *old_bp,
			   struct pram_xblock_desc *old_desc,
			   struct pram_xattr_header *header)
{
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);
	struct pram_xblock_desc *new_desc = NULL;
	unsigned long blocknr;
	struct pram_inode *pi;
	int error;
	char *new_bp = NULL;

	if (header) {
		new_desc = pram_xattr_cache_find(inode, header);
		if (new_desc) {
			new_bp = pram_get_block(sb,
				pram_get_block_off(sb, new_desc->blocknr));
			/* We found an identical block in the cache. */
			if (new_bp == old_bp) {
				ea_bdebug(new_desc->blocknr,
							"keeping this block");
			} else {
				/* The old block is released after updating
				   the inode.  */
				ea_bdebug(new_desc->blocknr, "reusing block");
				pram_memunlock_block(sb, new_bp);
				be32_add_cpu(&HDR(new_bp)->h_refcount, 1);
				pram_memlock_block(sb, new_bp);
				ea_bdebug(new_desc->blocknr, "refcount now=%d",
					be32_to_cpu(HDR(new_bp)->h_refcount));
			}
			blocknr = new_desc->blocknr;
			mutex_unlock(&new_desc->lock);
			desc_put(sb, new_desc);
		} else if (old_bp && header == HDR(old_bp)) {
			/* Keep this block. No need to lock the block as we
			   don't need to change the reference count. */
			new_bp = old_bp;
			pram_xattr_cache_insert(sb, old_desc->blocknr,
						HDR(new_bp)->h_hash);
			blocknr = old_desc->blocknr;
		} else {
			/* We need to allocate a new block */
			struct pram_xblock_desc *new_desc;

			error = pram_new_block(sb, &blocknr, 1);
			if (error)
				goto out;
			ea_idebug(inode, "creating block %lu", blocknr);
			new_desc = kmem_cache_alloc(pram_xblock_desc_cache,
						    GFP_KERNEL);
			if (!new_desc) {
				pram_free_block(sb, blocknr);
				error = -EIO;
				goto out;
			}
			xblock_desc_init_always(new_desc);
			new_desc->blocknr = blocknr;
			new_bp = pram_get_block(sb,
					       pram_get_block_off(sb, blocknr));
			if (!new_bp) {
				pram_free_block(sb, blocknr);
				kmem_cache_free(pram_xblock_desc_cache,
						new_desc);
				error = -EIO;
				goto out;
			}
			pram_memunlock_block(sb, new_bp);
			memcpy(new_bp, header, sb->s_blocksize);
			pram_memlock_block(sb, new_bp);
			insert_xblock_desc(sbi, new_desc);
			pram_xattr_cache_insert(sb, new_desc->blocknr,
						HDR(new_bp)->h_hash);
		}
	}

	/* Update the inode. */
	pi = pram_get_inode(sb, inode->i_ino);
	pram_memunlock_inode(sb, pi);
	pi->i_xattr = new_bp ? be64_to_cpu(pram_get_block_off(sb, blocknr)) : 0;
	inode->i_ctime = CURRENT_TIME_SEC;
	pi->i_ctime = cpu_to_be32(inode->i_ctime.tv_sec);
	pram_memlock_inode(sb, pi);

	error = 0;
	if (old_bp && old_bp != new_bp) {
		struct mb_cache_entry *ce;

		/* Here old_desc MUST be valid or we have a bug */
		BUG_ON(!old_desc);

		/*
		 * If there was an old block and we are no longer using it,
		 * release the old block.
		 */
		ce = mb_cache_entry_get(pram_xattr_cache,
					(struct block_device *)sbi,
					old_desc->blocknr);
		mutex_lock(&old_desc->lock);
		if (HDR(old_bp)->h_refcount == cpu_to_be32(1)) {
			/* Free the old block. */
			if (ce)
				mb_cache_entry_free(ce);
			ea_bdebug(old_desc->blocknr, "freeing");
			mutex_unlock(&old_desc->lock);
			/* Caller will call desc_put later */
			mark_free_desc(old_desc);
		} else {
			/* Decrement the refcount only. */
			pram_memunlock_block(sb, old_bp);
			be32_add_cpu(&HDR(old_bp)->h_refcount, -1);
			pram_memlock_block(sb, old_bp);
			if (ce)
				mb_cache_entry_release(ce);
			ea_bdebug(old_desc->blocknr, "refcount now=%d",
			be32_to_cpu(HDR(old_bp)->h_refcount));
			mutex_unlock(&old_desc->lock);
		}
	}

out:
	return error;
}

/*
 * pram_xattr_delete_inode()
 *
 * Free extended attribute resources associated with this inode. This
 * is called immediately before an inode is freed.
 */
void pram_xattr_delete_inode(struct inode *inode)
{
	char *bp = NULL;
	struct mb_cache_entry *ce;
	struct pram_inode *pi;
	struct pram_xblock_desc *desc;
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);
	unsigned long blocknr;

	pi = pram_get_inode(sb, inode->i_ino);
	if (!pi)
		goto cleanup;
	down_write(&PRAM_I(inode)->xattr_sem);
	if (!pi->i_xattr)
		goto cleanup;
	bp = pram_get_block(sb, be64_to_cpu(pi->i_xattr));
	if (!bp) {
		pram_err(sb, "inode %ld: block %llu read error", inode->i_ino,
			be64_to_cpu(pi->i_xattr));
		goto cleanup;
	}
	blocknr = pram_get_blocknr(sb, be64_to_cpu(pi->i_xattr));
	if (HDR(bp)->h_magic != cpu_to_be32(PRAM_XATTR_MAGIC)) {
		pram_err(sb, "inode %ld: bad block %llu", inode->i_ino,
			be64_to_cpu(pi->i_xattr));
		goto cleanup;
	}
	ce = mb_cache_entry_get(pram_xattr_cache,
				(struct block_device *)sbi, blocknr);
	desc = GET_DESC(sbi, blocknr);
	if (IS_ERR(desc))
		goto cleanup;
	mutex_lock(&desc->lock);
	if (HDR(bp)->h_refcount == cpu_to_be32(1)) {
		if (ce)
			mb_cache_entry_free(ce);
		mark_free_desc(desc);
	} else {
		be32_add_cpu(&HDR(bp)->h_refcount, -1);
		if (ce)
			mb_cache_entry_release(ce);
		ea_bdebug(blocknr, "refcount now=%d",
			be32_to_cpu(HDR(bp)->h_refcount));
		mutex_unlock(&desc->lock);
	}
	desc_put(sb, desc);

cleanup:
	up_write(&PRAM_I(inode)->xattr_sem);
}

/*
 * pram_xattr_put_super()
 *
 * This is called when a file system is unmounted.
 */
void pram_xattr_put_super(struct super_block *sb)
{
	struct pram_sb_info *sbi = PRAM_SB(sb);
	/*
	 * NOTE: we haven't got any block device to use with mb. Mb code
	 * doesn't use the pointer but it uses only the address as unique
	 * key so it's safe to use a "general purpose" address. We use
	 * super block info data as unique key. Maybe it'd be better to
	 * change mb code in order to use a generic void pointer to a
	 * generic id.
	 */
	mb_cache_shrink((struct block_device *)sbi);
	erase_tree(sbi, pram_xblock_desc_cache);
	kmem_cache_shrink(pram_xblock_desc_cache);
}


/*
 * pram_xattr_cache_insert()
 *
 * Create a new entry in the extended attribute cache, and insert
 * it unless such an entry is already in the cache.
 *
 * Returns 0, or a negative error number on failure.
 */
static int pram_xattr_cache_insert(struct super_block *sb,
				   unsigned long blocknr, u32 xhash)
{
	struct pram_sb_info *sbi = PRAM_SB(sb);
	__u32 hash = be32_to_cpu(xhash);
	struct mb_cache_entry *ce;
	int error;

	ce = mb_cache_entry_alloc(pram_xattr_cache, GFP_NOFS);
	if (!ce)
		return -ENOMEM;
	error = mb_cache_entry_insert(ce, (struct block_device *)sbi, blocknr,
				      hash);
	if (error) {
		mb_cache_entry_free(ce);
		if (error == -EBUSY) {
			ea_bdebug(blocknr, "already in cache");
			error = 0;
		}
	} else {
		ea_bdebug(blocknr, "inserting [%x]", (int)hash);
		mb_cache_entry_release(ce);
	}
	return error;
}

/*
 * pram_xattr_cmp()
 *
 * Compare two extended attribute blocks for equality.
 *
 * Returns 0 if the blocks are equal, 1 if they differ, and
 * a negative error number on errors.
 */
static int pram_xattr_cmp(struct pram_xattr_header *header1,
			  struct pram_xattr_header *header2)
{
	struct pram_xattr_entry *entry1, *entry2;

	entry1 = ENTRY(header1+1);
	entry2 = ENTRY(header2+1);
	while (!IS_LAST_ENTRY(entry1)) {
		if (IS_LAST_ENTRY(entry2))
			return 1;
		if (entry1->e_hash != entry2->e_hash ||
		    entry1->e_name_index != entry2->e_name_index ||
		    entry1->e_name_len != entry2->e_name_len ||
		    entry1->e_value_size != entry2->e_value_size ||
		    memcmp(entry1->e_name, entry2->e_name, entry1->e_name_len))
			return 1;
		if (entry1->e_value_block != 0 || entry2->e_value_block != 0)
			return -EIO;
		if (memcmp((char *)header1 + be16_to_cpu(entry1->e_value_offs),
			   (char *)header2 + be16_to_cpu(entry2->e_value_offs),
			   be32_to_cpu(entry1->e_value_size)))
			return 1;

		entry1 = PRAM_XATTR_NEXT(entry1);
		entry2 = PRAM_XATTR_NEXT(entry2);
	}
	if (!IS_LAST_ENTRY(entry2))
		return 1;
	return 0;
}

/*
 * pram_xattr_cache_find()
 *
 * Find an identical extended attribute block.
 *
 * Returns a locked extended block descriptor for the block found, or
 * NULL if such a block was not found or an error occurred.
 * The block, however, is not memory unlocked.
 */
static struct pram_xblock_desc *pram_xattr_cache_find(struct inode *inode,
					       struct pram_xattr_header *header)
{
	__u32 hash = be32_to_cpu(header->h_hash);
	struct mb_cache_entry *ce;
	struct pram_xblock_desc *desc;
	struct super_block *sb = inode->i_sb;
	struct pram_sb_info *sbi = PRAM_SB(sb);

	if (!header->h_hash)
		return NULL;  /* never share */
	ea_idebug(inode, "looking for cached blocks [%x]", (int)hash);
again:
	ce = mb_cache_entry_find_first(pram_xattr_cache,
					(struct block_device *)sbi, hash);
	while (ce) {
		char *bp;

		if (IS_ERR(ce)) {
			if (PTR_ERR(ce) == -EAGAIN)
				goto again;
			break;
		}

		bp = pram_get_block(sb, pram_get_block_off(sb, (unsigned long)ce->e_block));
		if (!bp) {
			pram_err(sb, "inode %ld: block %ld read error",
				inode->i_ino, (unsigned long) ce->e_block);
		} else {
			desc = LOOKUP_DESC(sbi, ce->e_block);
			if (!desc) {
				mb_cache_entry_release(ce);
				return NULL;
			}
			mutex_lock(&desc->lock);
			if (be32_to_cpu(HDR(bp)->h_refcount) >
				   PRAM_XATTR_REFCOUNT_MAX) {
				ea_idebug(inode, "block %ld refcount %d>%d",
					  (unsigned long) ce->e_block,
					  be32_to_cpu(HDR(bp)->h_refcount),
					  PRAM_XATTR_REFCOUNT_MAX);
			} else if (!pram_xattr_cmp(header, HDR(bp))) {
				mb_cache_entry_release(ce);
				return desc;
			}
			mutex_unlock(&desc->lock);
		}
		ce = mb_cache_entry_find_next(ce,
					      (struct block_device *)sbi,
					      hash);
	}
	return NULL;
}

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * pram_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
static inline void pram_xattr_hash_entry(struct pram_xattr_header *header,
					 struct pram_xattr_entry *entry)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__be32 *value = (__be32 *)((char *)header +
			be16_to_cpu(entry->e_value_offs));
		for (n = (be32_to_cpu(entry->e_value_size) +
		     PRAM_XATTR_ROUND) >> PRAM_XATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       be32_to_cpu(*value++);
		}
	}
	entry->e_hash = cpu_to_be32(hash);
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16

/*
 * pram_xattr_rehash()
 *
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void pram_xattr_rehash(struct pram_xattr_header *header,
			      struct pram_xattr_entry *entry)
{
	struct pram_xattr_entry *here;
	__u32 hash = 0;

	pram_xattr_hash_entry(header, entry);
	here = ENTRY(header+1);
	while (!IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       be32_to_cpu(here->e_hash);
		here = PRAM_XATTR_NEXT(here);
	}
	header->h_hash = cpu_to_be32(hash);
}

#undef BLOCK_HASH_SHIFT

static void init_xblock_desc_once(void *foo)
{
	struct pram_xblock_desc *desc = (struct pram_xblock_desc *) foo;

	xblock_desc_init_once(desc);
}

int __init init_pram_xattr(void)
{
	int ret = 0;
	pram_xattr_cache = mb_cache_create("pram_xattr", 6);
	if (!pram_xattr_cache) {
		ret = -ENOMEM;
		goto fail1;
	}

	pram_xblock_desc_cache = kmem_cache_create("pram_xblock_desc",
					     sizeof(struct pram_xblock_desc),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_xblock_desc_once);
	if (!pram_xblock_desc_cache) {
		ret = -ENOMEM;
		goto fail2;
	}

	return 0;
fail2:
	mb_cache_destroy(pram_xattr_cache);
fail1:
	return ret;
}

void exit_pram_xattr(void)
{
	mb_cache_destroy(pram_xattr_cache);
	kmem_cache_destroy(pram_xblock_desc_cache);
}
