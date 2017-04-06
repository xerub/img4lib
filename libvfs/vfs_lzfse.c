#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include "lzfse.h"
#include "vfs.h"
#include "vfs_internal.h"

struct file_ops_lzfse {
    struct file_ops_memory ops;
    FHANDLE other;
};

static int
lzfse_fsync(FHANDLE fd)
{
    FHANDLE other;
    struct file_ops_lzfse *ctx = (struct file_ops_lzfse *)fd;
    size_t csize;
    size_t total, written;
    uint8_t *aux, *buf;

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

    buf = malloc(total + 256);
    if (!buf) {
        return -1;
    }

    aux = malloc(lzfse_encode_scratch_size());
    if (!aux) {
        free(buf);
        return -1;
    }

    csize = lzfse_encode_buffer(buf, total + 256, MEMFD(fd)->buf, total, aux);
    free(aux);
    if (!csize) {
        free(buf);
        return -1;
    }

    other->lseek(other, 0, SEEK_SET);
    written = other->write(other, buf, csize);
    free(buf);
    if (written != csize) {
        return -1;
    }

    other->ftruncate(other, written);
  next:
    MEMFD(fd)->dirty = 0;
    return other->fsync(other);
}

static int
lzfse_close(FHANDLE fd)
{
    int rv, rc;
    FHANDLE other;
    struct file_ops_lzfse *ctx = (struct file_ops_lzfse *)fd;

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
lzfse_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_lzfse *ctx = (struct file_ops_lzfse *)fd;
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
lzfse_reopen(FHANDLE other, size_t usize)
{
    FHANDLE fd;
    size_t outlen;
    size_t csize;
    unsigned char hdr[4];
    unsigned char *buf, *dec, *aux;
    struct file_ops_lzfse *ctx;
    off_t where;

    if (!other) {
        return NULL;
    }
    if (other->flags == O_WRONLY) {
        goto closeit;
    }

    where = other->lseek(other, 0, SEEK_CUR);
    outlen = other->read(other, hdr, sizeof(hdr));
    if (outlen != sizeof(hdr)) {
        goto closeit;
    }

    if (GET_DWORD_BE(hdr, 0) != 'bvx2') {
        other->lseek(other, where, SEEK_SET);
        return other;
    }

    csize = other->length(other);
    if ((ssize_t)csize < 0) {
        goto closeit;
    }

    buf = malloc(csize);
    if (!buf) {
        goto closeit;
    }
    other->lseek(other, 0, SEEK_SET);
    outlen = other->read(other, buf, csize);
    if (outlen != csize) {
        goto freebuf;
    }

    if (usize) {
        /* we know exactly how much we want to decompress */
        dec = malloc(usize + 1);
        if (!dec) {
            goto freebuf;
        }
        aux = malloc(lzfse_decode_scratch_size());
        if (!aux) {
            free(dec);
            goto freebuf;
        }
        outlen = lzfse_decode_buffer(dec, usize + 1, buf, csize, aux);
        free(aux);
        free(buf);
        buf = dec;
        if (outlen != usize) {
            goto freebuf;
        }
        goto okay;
    }

    usize = csize * 4;
    dec = malloc(usize);
    if (!dec) {
        goto freebuf;
    }

    aux = malloc(lzfse_decode_scratch_size());
    if (!aux) {
        free(dec);
        goto freebuf;
    }

    while ((outlen = lzfse_decode_buffer(dec, usize, buf, csize, aux)) >= usize) {
        void *tmp = realloc(dec, usize *= 2);
        if (!tmp) {
            free(aux);
            free(dec);
            goto freebuf;
        }
        dec = tmp;
    }
    free(aux);
    free(buf);
    buf = dec;
    if (!outlen) {
        goto freebuf;
    }
    dec = realloc(buf, outlen);
    if (!dec) {
        goto freebuf;
    }
    buf = dec;

  okay:
    fd = memory_openex(malloc(sizeof(*ctx)), other->flags, buf, outlen);
    if (!fd) {
        goto freebuf;
    }
    ctx = (struct file_ops_lzfse *)fd;
    ctx->other = other;

    fd->ioctl = lzfse_ioctl;
    fd->fsync = lzfse_fsync;
    fd->close = lzfse_close;
    return fd;

  freebuf:
    free(buf);
  closeit:
    other->close(other);
    return NULL;
}
