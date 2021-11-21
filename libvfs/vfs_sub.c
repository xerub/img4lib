#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include "vfs.h"

struct file_ops_sub {
    struct file_ops ops;
    FHANDLE other;
    off_t start;
    size_t length;
    off_t reloff;
};

static int
sub_fsync(FHANDLE fd)
{
    FHANDLE other;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    if (!fd) {
        return -1;
    }
    other = ctx->other;
    return other->fsync(other);
}

static int
sub_close(FHANDLE fd)
{
    int rv, rc;
    FHANDLE other;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;

    if (!fd) {
        return -1;
    }
    other = ctx->other;

    rv = fd->fsync(fd);

    free(fd);
    rc = other->close(other);
    return rv ? rv : rc;
}

static ssize_t
sub_read(FHANDLE fd, void *buf, size_t count)
{
    FHANDLE other;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    ssize_t n;

    if (!fd) {
        return -1;
    }
    other = ctx->other;

    if (count > ctx->length - ctx->reloff) {
        count = ctx->length - ctx->reloff;
    }

    n = other->read(other, buf, count);
    if (n >= 0) {
        ctx->reloff += n;
    }
    return n;
}

static ssize_t
sub_write(FHANDLE fd, const void *buf, size_t count)
{
    FHANDLE other;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    ssize_t n;

    if (!fd) {
        return -1;
    }
    other = ctx->other;

    if (count > ctx->length - ctx->reloff) {
        count = ctx->length - ctx->reloff;
    }

    n = other->write(other, buf, count);
    if (n >= 0) {
        ctx->reloff += n;
    }
    return n;
}

static off_t
sub_lseek(FHANDLE fd, off_t offset, int whence)
{
    FHANDLE other;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    off_t where;

    if (!fd) {
        return -1;
    }
    other = ctx->other;

    switch (whence) {
        case SEEK_SET:
            offset += ctx->start;
            break;
        case SEEK_CUR:
            offset += ctx->reloff;
            break;
        case SEEK_END:
            offset += ctx->start + ctx->length;
            break;
        default:
            return -1;
    }
    if (offset < ctx->start || offset > (off_t)(ctx->start + ctx->length)) {
        return -1;
    }

    where = other->lseek(other, offset, SEEK_SET);
    if (where != offset) {
        return -1;
    }
    return ctx->reloff = where - ctx->start;
}

static int
sub_ftruncate(FHANDLE fd, off_t length)
{
    FHANDLE other;
    size_t start, total;
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    if (!fd) {
        return -1;
    }
    other = ctx->other;
    start = ctx->start;
    total = other->length(other);
    if ((ssize_t)total < 0 || start > total) {
        return -1;
    }
    if (length < 0) {
        length = total - start;
    }
    if (start + length > total) {
        return -1;
    }
    if (ctx->reloff > length) {
        ctx->reloff = length;
    }
    ctx->length = length;
    return 0;
}

static ssize_t
sub_length(FHANDLE fd)
{
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    if (!fd) {
        return -1;
    }
    return ctx->length;
}

static int
sub_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_sub *ctx = (struct file_ops_sub *)fd;
    FHANDLE other;
    int rv = -1;
    va_list ap;
    void *a;
    void *b;

    if (!fd) {
        return -1;
    }

    va_start(ap, req);
    a = va_arg(ap, void *);
    b = va_arg(ap, void *);
    other = ctx->other;
    rv = other->ioctl(other, req, a, b); /* XXX varargs */
    va_end(ap);
    return rv;
}

FHANDLE
sub_reopen(FHANDLE other, size_t offset, off_t length)
{
    struct file_ops_sub *ops;
    FHANDLE fd;

    if (!other) {
        return NULL;
    }

    ops = malloc(sizeof(*ops));
    if (!ops) {
        goto closeit;
    }
    fd = (FHANDLE)ops;

    ops->other = other;
    ops->start = offset;
    ops->reloff = 0;

    if (sub_ftruncate(fd, length)) {
        goto error;
    }
    if (sub_lseek(fd, 0, SEEK_SET)) {
        goto error;
    }

    ops->ops.read = sub_read;
    ops->ops.write = sub_write;
    ops->ops.lseek = sub_lseek;
    ops->ops.ioctl = sub_ioctl;
    ops->ops.ftruncate = sub_ftruncate;
    ops->ops.fsync = sub_fsync;
    ops->ops.close = sub_close;
    ops->ops.length = sub_length;
    ops->ops.flags = other->flags;
    return fd;

  error:
    free(ops);
  closeit:
    other->close(other);
    return NULL;
}
