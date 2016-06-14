
PMFS Introduction
=================

PMFS is a file system for persistent memory. The file system is optimized to be
lightweight and efficient in providing access to persistent memory that is
directly accessible via CPU load/store instructions. It manages the persistent
memory directly and avoids the block driver layer and page cache layer and thus
provides synchronous reads and writes to persistent area. It supports all the
existing POSIX style file system APIs so that the applications need not be
modified to use this file system. In addition, PMFS provides support for huge
pages to minimize TLB entry usage and speed up virtual address lookup. PMFS's
mmap interface can map a file's data directly into the process's address space
without any intermediate buffering. This file system has been validated using
DRAM to emulate persistent memory. Hence, PMFS also provides an option to load
the file system from a disk-based file into memory during mount and save the
file system from memory into the disk-based file during unmount. PMFS also
guarantees consistent and durable updates to the file system meta-data against
arbitrary system and power failures. PMFS uses journaling (undo log) to provide
consistent updates to meta-data.


Configuring PMFS
================

PMFS uses a physically contiguous area of DRAM (which is not used by the
kernel) as the file system space. To make sure that the kernel doesn't use a
certain contiguous physical memory area you can boot the kernel with 'memmap'
kernel command line option.  For more information on this, please see
Documentation/kernel-parameters.txt.

For example, adding 'memmap=2G$4G' to the kernel boot parameters will reserve
2G of memory, starting at 4G.  (You may have to escape the $ so it isn't
interpreted by GRUB 2, if you use that as your boot loader.)

After the OS has booted, you can initialize PMFS during mount command by
passing 'init=' mount option and using 'dir-index' to open the directory index.

For example,

<pre>#mount -t pmfs -o physaddr=0x100000000,dir-index,init=2G none /mnt/pmfs</pre>

The above command will create a PMFS file system in the 2GB region starting at
0x100000000 (4GB) and mount it at /mnt/pmfs.  There are many other mount time
options supported by pmfs. Some of the main options include:

wprotect: This option protects pmfs from stray writes (e.g., because of kernel
bugs). It makes sure that the file system is mapped read-only into the kernel
and makes it writable only for a brief period when writing to it. (EXPERIMENTAL,
Use with Caution).

jsize: This option specifies the journal size. Default is 4MB.

hugemmap: This option enables support for using huge pages in memory-mapped
files.

For full list of options, please refer to the source code.


Using Huge Pages with PMFS
==========================

PMFS supports the use of huge-pages through the fallocate(), and ftruncate()
system calls. These functions set the file size and also provide PMFS with a
hint about what data-block size to use (fallocate() also pre-allocates the
data-blocks).  For example, if we set the file size below 2MB, 4KB blocksize is
used.  If we set the file size between >= 2MB but < 1GB, 2MB block size is used,
and if we set the file size >= 1GB, 1GB block-size is used.  fallocate() or
ftruncate() should be called on a empty file (size 0) for the block-size hint
to be applied properly. So, a good way to use Huge Pages in PMFS is to open a
new file through the open() system call, and call fallocate() or ftruncate() to
set the file size and block-size hint.  Remember, that it is only a hint, so if
PMFS can't find enough free blocks of a particular size, it will try to use
smaller block-size.  If the block-size hint is not set, default 4KB block-size
will be used for file's data-blocks.


Current Limitations
===================

* PMFS uses a memory region not used by the kernel. Hence the memory needs to
be reserved by using the memmap= option or using BIOS ACPI tables.

* Because of multiple blocksize support, PMFS supports multiple max file
sizes. For example, if the file's block size is 4KB, the file can grow up to
512 GB in size, if blocksize is 2MB, file can grow up to 256 TB, and if the
blocksize is 1GB, the file can grow up to 128 PB.

* PMFS does not currently support extended attributes.

* PMFS currently only works with x86_64 kernels.


Contributing
============

Please send bug reports/comments/feedback to the PMFS development
list: linux-pmfs@lists.infradead.org
You are also encouraged to subscribe to the mailing list
by sending an email with the Subject line **subscribe** to
linux-pmfs-request@lists.infradead.org.

We prefer pull requests as patches sent to the mailing list.

Also feel free to join us on the IRC channel #pmfs on irc.oftc.net.
