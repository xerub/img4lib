#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lzss.h"
#include "vfs.h"
#include "vfs_internal.h"

struct file_ops_lzss {
    struct file_ops_memory ops;
    FHANDLE other;
    void *extra;
    size_t extrasz;
};

static int
lzss_fsync(FHANDLE fd)
{
    FHANDLE other;
    struct file_ops_lzss *ctx = (struct file_ops_lzss *)fd;
    uint32_t csize;
    uint32_t adler;
    size_t total, written;
    uint8_t *end, *buf;

    if (!fd) {
        return -1;
    }

    other = ctx->other;

    if (other->flags == O_RDONLY) {
        return 0;
    }
    if (!MEMFD(fd)->dirty) {
        goto next;
    }

    total = MEMFD(fd)->size;
    adler = lzadler32(MEMFD(fd)->buf, total);

    buf = malloc(0x180 + (total + 256));
    if (!buf) {
        return -1;
    }
    end = compress_lzss(buf + 0x180, total + 256, MEMFD(fd)->buf, total);
    csize = end - (buf + 0x180);

    PUT_DWORD_BE(buf,  0, 'comp');
    PUT_DWORD_BE(buf,  4, 'lzss');
    PUT_DWORD_BE(buf,  8, adler);
    PUT_DWORD_BE(buf, 12, total);
    PUT_DWORD_BE(buf, 16, csize);
    PUT_DWORD_BE(buf, 20, 1);
    memset(buf + 24, 0, 0x180 - 24);

    other->lseek(other, 0, SEEK_SET);
    written = other->write(other, buf, end - buf);
    free(buf);
    if (buf + written != end) {
        return -1;
    }
    written = other->write(other, ctx->extra, ctx->extrasz);
    if (written != ctx->extrasz) {
        return -1;
    }
    other->ftruncate(other, end - buf + written);
  next:
    MEMFD(fd)->dirty = 0;
    return other->fsync(other);
}

static int
lzss_close(FHANDLE fd)
{
    int rv, rc;
    FHANDLE other;
    struct file_ops_lzss *ctx = (struct file_ops_lzss *)fd;

    if (!fd) {
        return -1;
    }

    other = ctx->other;

    rv = fd->fsync(fd);

    free(ctx->extra);
    memory_close(fd);
    rc = other->close(other);
    return rv ? rv : rc;
}

static int
lzss_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_lzss *ctx = (struct file_ops_lzss *)fd;
    int rv = -1;
    va_list ap;

    if (!fd) {
        return -1;
    }

    va_start(ap, req);
    switch (req) {
        case IOCTL_MEM_GET_DATAPTR: {
            void **dst = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *dst = MEMFD(fd)->buf;
            *sz = MEMFD(fd)->size;
            rv = 0;
            break;
        }
        case IOCTL_LZSS_GET_EXTRA: {
            void **dst = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *dst = ctx->extra;
            *sz = ctx->extrasz;
            rv = 0;
            break;
        }
        case IOCTL_LZSS_SET_EXTRA: {
            void *old = ctx->extra;
            void *src = va_arg(ap, void *);
            size_t sz = va_arg(ap, size_t);
            ctx->extra = src;
            ctx->extrasz = sz;
            free(old);
            rv = 0;
            break;
        }
        default: {
            void *a = va_arg(ap, void *);
            void *b = va_arg(ap, void *);
            FHANDLE other = ctx->other;
            rv = other->ioctl(other, req, a, b); /* XXX varargs */
        }
    }
    va_end(ap);
    return rv;
}

FHANDLE
lzss_reopen(FHANDLE other)
{
    FHANDLE fd;
    size_t outlen;
    uint32_t csize;
    uint32_t usize;
    uint32_t adler;
    unsigned char hdr[20];
    unsigned char *buf, *dec;
    struct file_ops_lzss *ctx;
    off_t where;
    size_t tail;

    if (!other) {
        return NULL;
    }
    if (other->flags == O_WRONLY) {
        goto closeit;
    }

    where = other->lseek(other, 0, SEEK_CUR);
    outlen = other->read(other, hdr, sizeof(hdr));
    if (outlen != sizeof(hdr) || GET_DWORD_BE(hdr, 0) != 'comp' || GET_DWORD_BE(hdr, 4) != 'lzss') {
        other->lseek(other, where, SEEK_SET);
        return other;
    }

    csize = GET_DWORD_BE(hdr, 16);
    usize = GET_DWORD_BE(hdr, 12);

    buf = malloc(csize);
    if (!buf) {
        goto closeit;
    }
    outlen = other->lseek(other, 0x180, SEEK_SET);
    if (outlen != 0x180) {
        goto freebuf;
    }
    outlen = other->read(other, buf, csize);
    if (outlen != csize) {
        goto freebuf;
    }

    dec = malloc(usize);
    if (!dec) {
        goto freebuf;
    }

    outlen = decompress_lzss(dec, buf, csize);
    free(buf);
    buf = dec;
    if (outlen != usize) {
        goto freebuf;
    }
    adler = lzadler32(dec, usize);
    if (GET_DWORD_BE(hdr, 8) != adler) {
        fprintf(stderr, "adler mismatch: stored=%08x calculated=%08x\n", GET_DWORD_BE(hdr, 8), adler);
    }

    fd = memory_openex(malloc(sizeof(*ctx)), other->flags, buf, usize);
    if (!fd) {
        goto freebuf;
    }
    ctx = (struct file_ops_lzss *)fd;
    ctx->other = other;

    tail = other->length(other);
    if ((ssize_t)tail < 0 || tail < csize + 0x180) {
        goto error;
    }
    tail -= csize + 0x180;
    ctx->extra = malloc(tail);
    if (!ctx->extra) {
        goto error;
    }
    outlen = other->read(other, ctx->extra, tail);
    if (outlen != tail) {
        free(ctx->extra);
        goto error;
    }
    ctx->extrasz = tail;

    fd->ioctl = lzss_ioctl;
    fd->fsync = lzss_fsync;
    fd->close = lzss_close;
    return fd;

  error:
    fd->close(fd);
  freebuf:
    free(buf);
  closeit:
    other->close(other);
    return NULL;
}
