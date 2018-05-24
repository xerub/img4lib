#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef USE_CORECRYPTO
#   include <corecrypto/ccaes.h>
#elif USE_COMMONCRYPTO
#   include <CommonCrypto/CommonCrypto.h>
#else
#   include <openssl/aes.h>
#endif
#include "vfs.h"
#include "vfs_internal.h"

struct file_ops_enc {
    struct file_ops_memory ops;
    FHANDLE other;
    unsigned char iv[16];
    unsigned char key[32];
    int noencrypt;
};

static int
enc_fsync(FHANDLE fd)
{
    FHANDLE other;
    size_t written, total;
    struct file_ops_enc *ctx = (struct file_ops_enc *)fd;
    unsigned char *buf;
#ifndef USE_CORECRYPTO
#if USE_COMMONCRYPTO
    CCCryptorRef cryptor;
#else
    unsigned char theiv[16];
    AES_KEY encryptKey;
#endif
#endif

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

    other->lseek(other, 0, SEEK_SET);

    buf = MEMFD(fd)->buf;
    if (ctx->noencrypt) {
        written = other->write(other, buf, total);
        if (written != total) {
            return -1;
        }
        goto next;
    }
    {
#ifdef USE_CORECRYPTO
    cccbc_ctx_decl(cccbc_context_size(ccaes_cbc_encrypt_mode()), aesctx);
    cccbc_iv_decl(cccbc_block_size(ccaes_cbc_encrypt_mode()), iv_ctx);
    cccbc_set_iv(ccaes_cbc_encrypt_mode(), iv_ctx, ctx->iv);
    cccbc_init(ccaes_cbc_encrypt_mode(), aesctx, 256, ctx->key);
#elif USE_COMMONCRYPTO
    CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, 0, ctx->key, kCCKeySizeAES256, ctx->iv, &cryptor);
#else
    memcpy(theiv, ctx->iv, 16);
    AES_set_encrypt_key(ctx->key, 256, &encryptKey);
#endif
    while (total) {
        unsigned char tmp[0x1000];
        size_t chunk = sizeof(tmp);
        if (chunk > total) {
            chunk = total;
        }
        memcpy(tmp, buf, chunk);
        if (chunk & 15) {
            memset(tmp + chunk, 0, (16 - (chunk & 15)) & 15);
        }
#ifdef USE_CORECRYPTO
        cccbc_update(ccaes_cbc_encrypt_mode(), aesctx, iv_ctx, (chunk + 15) / 16, tmp, tmp);
#elif USE_COMMONCRYPTO
        CCCryptorUpdate(cryptor, tmp, (chunk + 15) & ~15, tmp, (chunk + 15) & ~15, NULL);
#else
        AES_cbc_encrypt(tmp, tmp, (chunk + 15) & ~15, &encryptKey, theiv, AES_ENCRYPT);
#endif
        written = other->write(other, tmp, chunk);
        if (written != chunk) {
#ifdef USE_CORECRYPTO
            cccbc_ctx_clear(cccbc_context_size(ccaes_cbc_encrypt_mode()), aesctx);
#elif USE_COMMONCRYPTO
            CCCryptorRelease(cryptor);
#endif
            return -1;
        }
        buf += chunk;
        total -= chunk;
    }
#ifdef USE_CORECRYPTO
    cccbc_ctx_clear(cccbc_context_size(ccaes_cbc_encrypt_mode()), aesctx);
#elif USE_COMMONCRYPTO
    CCCryptorRelease(cryptor);
#endif
    }

  next:
    MEMFD(fd)->dirty = 0;
    return other->fsync(other);
}

static int
enc_close(FHANDLE fd)
{
    int rv, rc;
    FHANDLE other;
    struct file_ops_enc *ctx = (struct file_ops_enc *)fd;

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
enc_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_enc *ctx = (struct file_ops_enc *)fd;
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
        case IOCTL_ENC_SET_NOENC: {
            MEMFD(fd)->dirty = 1;
            ctx->noencrypt = 1;
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
enc_reopen(FHANDLE other, const unsigned char iv[16], const unsigned char key[32])
{
    FHANDLE fd;
    size_t n, total;
    struct file_ops_enc *ctx;
    unsigned char *buf;
    unsigned char theiv[16];
#if !defined(USE_CORECRYPTO) && !USE_COMMONCRYPTO
    AES_KEY decryptKey;
#endif

    if (!other) {
        return NULL;
    }
    if (other->flags == O_WRONLY) {
        goto closeit;
    }

    if (key == NULL) {
        return other;
    }

    total = other->length(other);
    if ((ssize_t)total < 0) {
        goto closeit;
    }
    buf = calloc(1, (total + 15) & ~15);
    if (!buf) {
        goto closeit;
    }

    fd = memory_openex(malloc(sizeof(*ctx)), other->flags, buf, total);
    if (!fd) {
        goto freebuf;
    }
    ctx = (struct file_ops_enc *)fd;
    ctx->other = other;

    other->lseek(other, 0, SEEK_SET);
    n = other->read(other, buf, total);
    if (n != total) {
        goto error;
    }
    if (iv) {
        memcpy(theiv, iv, 16);
    } else {
        memset(theiv, 0, 16);
    }
#ifdef USE_CORECRYPTO
    cccbc_one_shot(ccaes_cbc_decrypt_mode(), 32, key, theiv, (n + 15) / 16, buf, buf);
#elif USE_COMMONCRYPTO
    CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, kCCKeySizeAES256, theiv, buf, (n + 15) & ~15, buf, (n + 15) & ~15, NULL);
#else
    AES_set_decrypt_key(key, 256, &decryptKey);
    AES_cbc_encrypt(buf, buf, (n + 15) & ~15, &decryptKey, theiv, AES_DECRYPT);
#endif
    memcpy(ctx->key, key, 32);
    if (iv) {
        memcpy(ctx->iv, iv, 16);
    }
    ctx->noencrypt = 0;

    fd->ioctl = enc_ioctl;
    fd->fsync = enc_fsync;
    fd->close = enc_close;
    return fd;

  error:
    fd->close(fd);
  freebuf:
    free(buf);
  closeit:
    other->close(other);
    return NULL;
}
