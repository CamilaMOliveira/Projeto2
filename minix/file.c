/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include <linux/uio.h>
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

ssize_t cipher_file_write_iter(struct kiocb *iocb, struct iov_iter *from);

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= cipher_file_write_iter, //generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	printk("@@@ minix_setattr em file.c \n");

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

ssize_t cipher_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t result, nbytes, in_size;
	char *buffer = kmalloc (sizeof (char) * 256,GFP_KERNEL);
	struct iovec *iov_page = NULL;
	struct iovec *in_iov = NULL;
	unsigned int in_iovs = 0;

	/*iov_page = (struct iovec *) __get_free_page(GFP_KERNEL);
	struct iovec *iov = iov_page;

	in_iov = iov;
	in_iovs = 1;

	in_size = iov_length(in_iov, in_iovs);

	iov_iter_init(from, WRITE, in_iov, in_iovs, in_size);*/

	nbytes = copy_from_iter(buffer, 4, from);

	result = generic_file_write_iter(iocb, from);

	printk("COPY TO BUFFER =========== %s ===========\n",buffer);

	return result;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
