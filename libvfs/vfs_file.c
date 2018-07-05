#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vfs.h"
#include "vfs_internal.h"

struct file_ops_file {
    struct file_ops ops;
    int fd;
};

static int
file_fsync(FHANDLE fd_)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return fsync(fd->fd);
}

static int
file_close(FHANDLE fd_)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    close(fd->fd);
    free(fd);
    return 0;
}

static ssize_t
file_read(FHANDLE fd_, void *buf, size_t count)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return read(fd->fd, buf, count);
}

static ssize_t
file_write(FHANDLE fd_, const void *buf, size_t count)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return write(fd->fd, buf, count);
}

static off_t
file_lseek(FHANDLE fd_, off_t offset, int whence)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return lseek(fd->fd, offset, whence);
}

static int
file_ioctl(FHANDLE fd_, unsigned long req, ...)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return -1;
}

static int
file_ftruncate(FHANDLE fd_, off_t length)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    if (!fd) {
        return -1;
    }
    return ftruncate(fd->fd, length);
}

static ssize_t
file_length(FHANDLE fd_)
{
    struct file_ops_file *fd = (struct file_ops_file *)fd_;
    int rv;
    struct stat st;
    if (!fd) {
        return -1;
    }
    rv = fstat(fd->fd, &st);
    if (rv) {
        return -1;
    }
    return st.st_size;
}

FHANDLE
file_open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    struct file_ops_file *ops;
    ops = malloc(sizeof(*ops));
    if (!ops) {
        return NULL;
    }
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    ops->fd = open(pathname, flags, mode);
    if (ops->fd < 0) {
        free(ops);
        return NULL;
    }
    ops->ops.flags = flags & O_ACCMODE;
    ops->ops.read = file_read;
    ops->ops.write = file_write;
    ops->ops.lseek = file_lseek;
    ops->ops.ioctl = file_ioctl;
    ops->ops.ftruncate = file_ftruncate;
    ops->ops.fsync = file_fsync;
    ops->ops.close = file_close;
    ops->ops.length = file_length;
    return (FHANDLE)ops;
}
