#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef USE_LIBCOMPRESSION
typedef enum {
    COMPRESSION_LZFSE       = 0x801,
    COMPRESSION_LZFSE_SMALL = 0x891,
} compression_algorithm;
size_t compression_encode_buffer(uint8_t *restrict dst_buffer, size_t dst_size, const uint8_t *restrict src_buffer, size_t src_size, void *restrict scratch_buffer, compression_algorithm algorithm);
size_t compression_decode_buffer(uint8_t *restrict dst_buffer, size_t dst_size, const uint8_t *restrict src_buffer, size_t src_size, void *restrict scratch_buffer, compression_algorithm algorithm);
#define lzfse_decode_buffer(dst_buffer, dst_size, src_buffer, src_size, scratch_buffer) compression_decode_buffer(dst_buffer, dst_size, src_buffer, src_size, scratch_buffer, COMPRESSION_LZFSE_SMALL)
#define lzfse_encode_buffer(dst_buffer, dst_size, src_buffer, src_size, scratch_buffer) compression_encode_buffer(dst_buffer, dst_size, src_buffer, src_size, scratch_buffer, COMPRESSION_LZFSE_SMALL)
#else
#include <stdio.h>
#include "lzfse.h"
#endif
#include "vfs.h"
#include "vfs_internal.h"
#include "lzss.h"

struct file_ops_lzfse {
    struct file_ops_memory ops;
    FHANDLE other;
    int convert;
};

static int
lzfse_fsync(FHANDLE fd)
{
    FHANDLE other;
    struct file_ops_lzfse *ctx = (struct file_ops_lzfse *)fd;
    size_t csize;
    size_t total, written;
    uint8_t *buf;

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

    if (ctx->convert == 1) {
        uint32_t adler;
        uint8_t *end, *ptr = MEMFD(fd)->buf;

        if (total >= 24 && GET_DWORD_BE(ptr, 0) == 0xcafebabe && GET_DWORD_BE(ptr, 4) == 1) {
            total = GET_DWORD_BE(ptr, 20);
            ptr += GET_DWORD_BE(ptr, 16);
        }

        adler = lzadler32(ptr, total);

        buf = malloc(0x180 + (total + 256));
        if (!buf) {
            return -1;
        }
        end = compress_lzss(buf + 0x180, total + 256, ptr, total);
        csize = end - buf;

        PUT_DWORD_BE(buf,  0, 'comp');
        PUT_DWORD_BE(buf,  4, 'lzss');
        PUT_DWORD_BE(buf,  8, adler);
        PUT_DWORD_BE(buf, 12, total);
        PUT_DWORD_BE(buf, 16, csize - 0x180);
        PUT_DWORD_BE(buf, 20, 1);
        memset(buf + 24, 0, 0x180 - 24);
        goto okay;
    }
    if (ctx->convert == -1) {
        csize = total;
        buf = malloc(total);
        if (!buf) {
            return -1;
        }
        memcpy(buf, MEMFD(fd)->buf, total);
        goto okay;
    }

    buf = malloc(total + 256);
    if (!buf) {
        return -1;
    }

#ifndef USE_LIBCOMPRESSION
    // XXX we're using the public library, which doesn't support COMPRESSION_LZFSE_SMALL
    fprintf(stderr, "[w] lzfse encoding\n");
#endif
    csize = lzfse_encode_buffer(buf, total + 256, MEMFD(fd)->buf, total, NULL);
    if (!csize) {
        free(buf);
        return -1;
    }

  okay:
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
        case IOCTL_LZFSE_SET_LZSS: {
            MEMFD(fd)->dirty = 1;
            ctx->convert = 1;
            rv = 0;
            break;
        }
        case IOCTL_LZFSE_SET_NOCOMP: {
            MEMFD(fd)->dirty = 1;
            ctx->convert = -1;
            rv = 0;
            break;
        }
        case IOCTL_LZFSE_GET_LENGTH: {
            uint64_t *usize = va_arg(ap, uint64_t *);
            *usize = MEMFD(fd)->size;
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
    unsigned char *buf, *dec;
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
    if (outlen != sizeof(hdr) || GET_DWORD_BE(hdr, 0) != 'bvx2') {
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
        outlen = lzfse_decode_buffer(dec, usize + 1, buf, csize, NULL);
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

    while ((outlen = lzfse_decode_buffer(dec, usize, buf, csize, NULL)) >= usize) {
        void *tmp = realloc(dec, usize *= 2);
        if (!tmp) {
            free(dec);
            goto freebuf;
        }
        dec = tmp;
    }
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
    ctx->convert = 0;

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
