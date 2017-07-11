#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vfs.h"
#include "vfs_internal.h"

static int
memory_fsync(FHANDLE fd_)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    if (!fd) {
        return -1;
    }
    return 0;
}

int
memory_close(FHANDLE fd_)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    if (!fd) {
        return -1;
    }
    fd->free(fd->buf);
    free(fd);
    return 0;
}

static ssize_t
memory_read(FHANDLE fd_, void *buf, size_t count)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    if (!fd) {
        return -1;
    }
    if (fd->position > fd->size) {
        return 0;
    }
    if (count > fd->size - fd->position) {
        count = fd->size - fd->position;
    }
    memmove(buf, fd->buf + fd->position, count);
    fd->position += count;
    return count;
}

static ssize_t
memory_write(FHANDLE fd_, const void *buf, size_t count)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    size_t end;
    if (!fd || fd_->flags == O_RDONLY) {
        return -1;
    }
    end = fd->position + count;
    if (end > fd->size) {
        unsigned char *tmp = fd->realloc(fd->buf, end);
        if (!tmp) {
            count = fd->size - fd->position;
        } else {
            fd->buf = tmp;
            fd->size = end;
        }
    }
    fd->dirty = 1;
    memmove(fd->buf + fd->position, buf, count);
    fd->position += count;
    return count;
}

static off_t
memory_lseek(FHANDLE fd_, off_t offset, int whence)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    off_t position;
    if (!fd) {
        return -1;
    }
    switch (whence) {
        case SEEK_SET:
            position = offset;
            break;
        case SEEK_CUR:
            position = fd->position + offset;
            break;
        case SEEK_END:
            position = fd->size + offset;
            break;
        default:
            return -1;
    }
    if (position < 0) {
        return -1;
    }
    if ((size_t)position > fd->size) {
        size_t gap;
        unsigned char *tmp;
        if (fd_->flags == O_RDONLY) {
            return -1;
        }
        gap = position - fd->size;
        tmp = fd->realloc(fd->buf, position);
        if (!tmp) {
            return -1;
        }
        fd->dirty = 1;
        memset(tmp + fd->size, 0, gap);
        fd->buf = tmp;
        fd->size = position;
    }
    fd->position = position;
    return fd->position;
}

static int
memory_ioctl(FHANDLE fd_, unsigned long req, ...)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    int rv = -1;
    va_list ap;

    if (!fd) {
        return -1;
    }

    va_start(ap, req);
    switch (req) {
        case IOCTL_MEM_GET_DATAPTR:
        case IOCTL_MEM_GET_BACKING: {
            void **buf = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *buf = fd->buf;
            *sz = fd->size;
            rv = 0;
            break;
        }
        case IOCTL_MEM_SET_FUNCS: {
            fd->realloc = va_arg(ap, realloc_t);
            fd->free = va_arg(ap, free_t);
            rv = 0;
            break;
        }
    }
    va_end(ap);
    return rv;
}

static int
memory_ftruncate(FHANDLE fd_, off_t length)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    void *tmp;
    if (!fd || fd_->flags == O_RDONLY) {
        return -1;
    }
    fd->size = length;
    fd->dirty = 1;
    tmp = fd->realloc(fd->buf, length);
    if (tmp) {
        fd->buf = tmp;
    }
    return 0;
}

static ssize_t
memory_length(FHANDLE fd_)
{
    struct file_ops_memory *fd = (struct file_ops_memory *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->size;
}

FHANDLE
memory_openex(struct file_ops_memory *ops, int flags, void *buf, size_t size)
{
    if (!ops) {
        return NULL;
    }
    ops->buf = buf;
    if (!buf && size) {
        ops->buf = calloc(1, size);
        if (!ops->buf) {
            free(ops);
            return NULL;
        }
    }
    ops->size = size;
    ops->position = 0;
    ops->dirty = 0;
    ops->realloc = realloc;
    ops->free = free;
    ops->ops.flags = flags & O_ACCMODE;
    ops->ops.read = memory_read;
    ops->ops.write = memory_write;
    ops->ops.lseek = memory_lseek;
    ops->ops.ioctl = memory_ioctl;
    ops->ops.ftruncate = memory_ftruncate;
    ops->ops.fsync = memory_fsync;
    ops->ops.close = memory_close;
    ops->ops.length = memory_length;
    return (FHANDLE)ops;
}

FHANDLE
memory_open(int flags, void *buf, size_t size)
{
    return memory_openex(malloc(sizeof(struct file_ops_memory)), flags, buf, size);
}

FHANDLE
memory_open_from_file(const char *filename, int flags)
{
    FHANDLE pfd;
    size_t n, size;
    unsigned char *buf;
    FHANDLE fd = file_open(filename, O_RDONLY);
    if (!fd) {
        return NULL;
    }
    size = fd->length(fd);
    if ((ssize_t)size < 0) {
        fd->close(fd);
        return NULL;
    }
    buf = malloc(size);
    if (!buf) {
        fd->close(fd);
        return NULL;
    }
    n = fd->read(fd, buf, size);
    fd->close(fd);
    if (n != size) {
        free(buf);
        return NULL;
    }
    pfd = memory_open(flags, buf, size);
    if (!pfd) {
        free(buf);
    }
    return pfd;
}
