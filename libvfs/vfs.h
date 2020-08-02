#ifndef VFS_H_included
#define VFS_H_included

typedef struct file_ops *FHANDLE;

struct file_ops {
    ssize_t (*read)(FHANDLE fd, void *buf, size_t count);
    ssize_t (*write)(FHANDLE fd, const void *buf, size_t count);
    off_t (*lseek)(FHANDLE fd, off_t offset, int whence);
    int (*ioctl)(FHANDLE fd, unsigned long request, ...);
    int (*ftruncate)(FHANDLE fd, off_t length);
    int (*fsync)(FHANDLE fd);
    int (*close)(FHANDLE fd);
    ssize_t (*length)(FHANDLE fd);	/* convenience */
    int flags;
};

#define IOCTL_MEM_GET_DATAPTR   10	/* (void **, size_t *) // working data of current file */
#define IOCTL_MEM_GET_BACKING   11	/* (void **, size_t *) // underlying backing store */
#define IOCTL_MEM_SET_FUNCS     12	/* (realloc_t, free_t) */
#define IOCTL_ENC_SET_NOENC     30	/* (void) */
#define IOCTL_LZSS_GET_EXTRA    40	/* (void **, size_t *) */
#define IOCTL_LZSS_SET_EXTRA    41	/* (void *, size_t) */
#define IOCTL_LZFSE_SET_LZSS    42	/* (void) */
#define IOCTL_LZFSE_SET_NOCOMP  43	/* (void) */
#define IOCTL_LZFSE_GET_LENGTH  44	/* (unsigned long long *) */

#define IOCTL_IMG4_GET_TYPE     60	/* (unsigned *) */
#define IOCTL_IMG4_SET_TYPE     61	/* (unsigned) */
#define IOCTL_IMG4_GET_MANIFEST 62	/* (void **, size_t *) */
#define IOCTL_IMG4_SET_MANIFEST 63	/* (void *, size_t) */
#define IOCTL_IMG4_GET_NONCE    64	/* (unsigned long long *) */
#define IOCTL_IMG4_SET_NONCE    65	/* (unsigned long long) */
#define IOCTL_IMG4_GET_KEYBAG   66	/* (void **, size_t *) */
#define IOCTL_IMG4_SET_KEYBAG   67	/* (void *, size_t) */
#define IOCTL_IMG4_GET_KEYBAG2  68	/* (unsigned char[48], unsigned char[48]) */
#define IOCTL_IMG4_SET_KEYBAG2  69	/* (unsigned char[48], unsigned char[48]) */
#define IOCTL_IMG4_GET_VERSION  70	/* (void **, size_t *) */
#define IOCTL_IMG4_SET_VERSION  71	/* (void *, size_t) */
#define IOCTL_IMG4_EVAL_TRUST   90	/* (void *) */

#define FLAG_IMG4_SKIP_DECOMPRESSION    (1 << 0)
#define FLAG_IMG4_VERIFY_HASH           (1 << 1)
#define FLAG_IMG4_UPDATE_HASH           (1 << 2)

typedef void (*free_t)(void *ptr);
typedef void *(*realloc_t)(void *ptr, size_t size);

FHANDLE file_open(const char *pathname, int flags, ...);

/*
 * buf is not freed on error, but is freed on close (see IOCTL_MEM_SET_FUNCS)
 * buf may get reallocated any time. IOCTL_MEM_GET_DATAPTR to access the data
 */
FHANDLE memory_open(int flags, void *buf, size_t size);
FHANDLE memory_open_from_file(const char *filename, int flags);

/* these functions close 'other' in case of failure.
 * writing, closing or altering 'other' is forbidden,
 * though you may ioctl(GET) after fsync() the parent
 */
FHANDLE enc_reopen(FHANDLE other, const unsigned char iv[16], const unsigned char key[32]);
FHANDLE lzss_reopen(FHANDLE other);
FHANDLE lzfse_reopen(FHANDLE other, size_t usize);		/* pass usize=0 to decompress as much as possible */
FHANDLE sub_reopen(FHANDLE other, off_t offset, size_t length);	/* pass length<0 to slice to the end of file */
FHANDLE img4_reopen(FHANDLE other, const unsigned char *ivkey, int flags);

#endif
