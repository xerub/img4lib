#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "libvfs/vfs.h"

#define FOURCC(tag) (unsigned char)((tag) >> 24), (unsigned char)((tag) >> 16), (unsigned char)((tag) >> 8), (unsigned char)(tag)

static int
str2hex(int buflen, unsigned char *buf, const char *str)
{
    unsigned char *ptr = buf;
    int seq = -1;
    while (buflen > 0) {
        int nibble = *str++;
        if (nibble >= '0' && nibble <= '9') {
            nibble -= '0';
        } else {
            nibble |= 0x20;
            if (nibble < 'a' || nibble > 'f') {
                break;
            }
            nibble -= 'a' - 10;
        }
        if (seq >= 0) {
            *buf++ = (seq << 4) | nibble;
            buflen--;
            seq = -1;
        } else {
            seq = nibble;
        }
    }
    return buf - ptr;
}

static int
write_file(const char *name, void *buf, size_t size)
{
    FHANDLE out = file_open(name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (!out) {
        return -1;
    }
    out->write(out, buf, size);
    return out->close(out);
}

int
main(int argc, char **argv)
{
    FHANDLE fd;
    FHANDLE in;
    size_t size;
    uint64_t nonce;
    unsigned type;
    unsigned char *buf;
    size_t sz;
    int rv;

    unsigned char ivkey[16 + 32];
    str2hex(16 + 32, ivkey, "a6ff60f2fcf3cdcaaf735e1683418ff56828540cd92ac15f3144ed4dc9d5bcb34c01cc8154bc22c3658d82b6c439340b");
#if 0
    buf = calloc(1, 4);
    fd = lzss_reopen(enc_reopen(sub_reopen(file_open("kc_iPhone6,1_9.0_13A344.bin", O_RDONLY), 51, -1/*11062960*/), ivkey, ivkey + 16));
    if (fd) {
        sz = fd->read(fd, buf, 4);
        printf("%zd: %02x %02x %02x %02x\n", sz, buf[0], buf[1], buf[2], buf[3]);
        fd->close(fd);
    }
    return 0;
#endif

    //FHANDLE orig;
    //fd = img4_reopen(orig = memory_open_from_file("kc_iPhone6,1_9.0_13A344.bin", O_RDWR), ivkey, 0);
    fd = img4_reopen(file_open("kc_iPhone6,1_9.0_13A344.bin", O_RDWR), ivkey, 0);
    if (!fd) {
        fprintf(stderr, "cannot parse\n");
        return -1;
    }

    /* print info */
    rv = fd->ioctl(fd, IOCTL_IMG4_GET_TYPE, &type);
    if (rv) {
        fprintf(stderr, "cannot identify\n");
        fd->close(fd);
        return -1;
    }
    printf("%c%c%c%c\n", FOURCC(type));

    /* get the image: we could fd->read(fd, buf, sz) but why waste memory? */
    rv = fd->ioctl(fd, IOCTL_MEM_GET_DATAPTR, &buf, &sz);
    if (rv) {
        fprintf(stderr, "cannot get data\n");
        fd->close(fd);
        return -1;
    }
    rv = write_file("_image", buf, sz);
    if (rv) {
        fprintf(stderr, "cannot create image file\n");
        fd->close(fd);
        return -1;
    }

    /* get the extra */
    rv = fd->ioctl(fd, IOCTL_LZSS_GET_EXTRA, &buf, &sz);
    if (rv == 0) {
        rv = write_file("_extra", buf, sz);
        if (rv) {
            fprintf(stderr, "cannot create extra file\n");
            fd->close(fd);
            return -1;
        }
    } else {
        fprintf(stderr, "no extra\n");
    }

    /* get the manifest */
    rv = fd->ioctl(fd, IOCTL_IMG4_GET_MANIFEST, &buf, &sz);
    if (rv == 0) {
        rv = write_file("_manifest", buf, sz);
        if (rv) {
            fprintf(stderr, "cannot create manifest file\n");
            fd->close(fd);
            return -1;
        }
    } else {
        fprintf(stderr, "no manifest\n");
    }

    /* get the keybag: note that the only way to get it is by ioctl() */
    rv = fd->ioctl(fd, IOCTL_IMG4_GET_KEYBAG, &buf, &sz);
    if (rv == 0) {
        rv = write_file("_keybag", buf, sz);
        if (rv) {
            fprintf(stderr, "cannot create keybag file\n");
            fd->close(fd);
            return -1;
        }
    } else {
        fprintf(stderr, "no keybag\n");
    }

    /* get the nonce: note that the only way to get it is by ioctl() */
    rv = fd->ioctl(fd, IOCTL_IMG4_GET_NONCE, &nonce);
    if (rv == 0) {
        printf("nonce: 0x%llx\n", nonce);
    } else {
        fprintf(stderr, "no nonce\n");
    }

    /* set the manifest */
    in = file_open("manifest.im4m", O_RDONLY);
    if (in) {
        sz = in->length(in);
        buf = malloc(sz);
        if (!buf) {
            fprintf(stderr, "out of memory\n");
            in->close(in);
            fd->close(fd);
            return -1;
        }
        size = in->read(in, buf, sz);
        in->close(in);
        if (size != sz) {
            fprintf(stderr, "cannot read manifest\n");
            fd->close(fd);
            return -1;
        }
        rv = fd->ioctl(fd, IOCTL_IMG4_SET_MANIFEST, buf, sz);
        free(buf);
        if (rv) {
            fprintf(stderr, "cannot set manifest\n");
            fd->close(fd);
            return -1;
        }

        /* set the nonce */
        rv = fd->ioctl(fd, IOCTL_IMG4_SET_NONCE, 0x1122334455667788);
        if (rv) {
            fprintf(stderr, "cannot set nonce\n");
            fd->close(fd);
            return -1;
        }
    } else {
        fprintf(stderr, "cannot read manifest\n");
    }

    /* set new type */
    rv = fd->ioctl(fd, IOCTL_IMG4_SET_TYPE, 'rkrn');
    if (rv) {
        fprintf(stderr, "cannot set type\n");
        fd->close(fd);
        return -1;
    }

    /* leave it decrypted */
    rv = fd->ioctl(fd, IOCTL_ENC_SET_NOENC);
    if (rv) {
        fprintf(stderr, "failed set decrypt\n");
        fd->close(fd);
        return -1;
    }

    /* patches */
    unsigned char patch_AMFI[] = { 0xE0, 0x03, 0x00, 0x32, 0xC0, 0x03, 0x5F, 0xD6 };
    fd->lseek(fd, 0x6AF484, SEEK_SET);
    fd->write(fd, patch_AMFI, sizeof(patch_AMFI));

    unsigned char patch_MAC[] = { 0x00, 0x00, 0x80, 0x52 };
    fd->lseek(fd, 0x4823CC/*0xF5595C*/, SEEK_SET);
    fd->write(fd, patch_MAC, sizeof(patch_MAC));

    //fd->fsync(fd);
    //rv = orig->ioctl(orig, IOCTL_MEM_GET_DATAPTR, &buf, &sz);
    //write_file("_output", buf, sz);

    rv = fd->close(fd);
    printf("%d\n", rv);
    return 0;
}
