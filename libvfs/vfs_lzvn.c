#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lzss.h"
#include "LZVN/FastCompression.h"
#include "vfs.h"
#include "vfs_internal.h"

struct file_ops_lzvn {
    struct file_ops_memory ops;
    FHANDLE other;
};

static uint8_t *
compress_lzvn(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srclen)
{
    size_t n = lzvn_encode_work_size();
    char *ws = malloc(n);
    if (!ws) {
        return 0;
    }
    n = lzvn_encode(dst, dstlen, src, srclen, ws);
    free(ws);
    return dst + n;
}

static int
lzvn_fsync(FHANDLE fd)
{
    FHANDLE other;
    struct file_ops_lzvn *ctx = (struct file_ops_lzvn *)fd;
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
    end = compress_lzvn(buf + 0x180, total + 256, MEMFD(fd)->buf, total);
    csize = end - (buf + 0x180);

    PUT_DWORD_BE(buf,  0, 'comp');
    PUT_DWORD_BE(buf,  4, 'lzvn');
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
    other->ftruncate(other, written);
  next:
    MEMFD(fd)->dirty = 0;
    return other->fsync(other);
}

static int
lzvn_close(FHANDLE fd)
{
    int rv, rc;
    FHANDLE other;
    struct file_ops_lzvn *ctx = (struct file_ops_lzvn *)fd;

    if (!fd) {
        return -1;
    }

    other = ctx->other;

    rv = fd->fsync(fd);

    memory_close(fd);
    rc = other->close(other);
    return rv ? rv : rc;
}

static int
lzvn_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_lzvn *ctx = (struct file_ops_lzvn *)fd;
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
lzvn_reopen(FHANDLE other)
{
    FHANDLE fd;
    size_t outlen;
    uint32_t csize;
    uint32_t usize;
    uint32_t adler;
    unsigned char hdr[20];
    unsigned char *buf, *dec;
    struct file_ops_lzvn *ctx;
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
    if (outlen != sizeof(hdr) || GET_DWORD_BE(hdr, 0) != 'comp' || GET_DWORD_BE(hdr, 4) != 'lzvn') {
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

    outlen = lzvn_decode(dec, usize, buf, csize);
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
    ctx = (struct file_ops_lzvn *)fd;
    ctx->other = other;

    tail = other->length(other);
    if ((ssize_t)tail < 0 || tail < csize + 0x180) {
        goto error;
    }

    fd->ioctl = lzvn_ioctl;
    fd->fsync = lzvn_fsync;
    fd->close = lzvn_close;
    return fd;

  error:
    fd->close(fd);
  freebuf:
    free(buf);
  closeit:
    other->close(other);
    return NULL;
}
