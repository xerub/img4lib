#ifndef VFS_INTERNAL_H_included
#define VFS_INTERNAL_H_included

/* when we know we *are* a memory-backed file, skip the bullshit */
#define MEMFD(fd) ((struct file_ops_memory *)fd)

struct file_ops_memory {
    struct file_ops ops;
    realloc_t realloc;
    free_t free;
    unsigned char *buf;
    size_t size;
    size_t position;
    int dirty;
};

FHANDLE memory_openex(struct file_ops_memory *ops, int flags, void *buf, size_t size);
int memory_ftruncate(FHANDLE fd, off_t length);
int memory_close(FHANDLE fd);

#if defined(__LITTLE_ENDIAN__) || defined(__x86_64__) || defined(__i386__) /*XXX __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__*/
#define GET_DWORD_BE(data, offset) __builtin_bswap32(*(uint32_t *)((char *)(data) + (offset)))
#define PUT_DWORD_BE(data, offset, value) *(uint32_t *)((char *)(data) + (offset)) = __builtin_bswap32(value)
#define GET_QWORD_BE(data, offset) __builtin_bswap64(*(uint64_t *)((char *)(data) + (offset)))
#define PUT_QWORD_BE(data, offset, value) *(uint64_t *)((char *)(data) + (offset)) = __builtin_bswap64(value)
#else
#define GET_DWORD_BE(data, offset) *(uint32_t *)((char *)(data) + (offset))
#define PUT_DWORD_BE(data, offset, value) *(uint32_t *)((char *)(data) + (offset)) = (value)
#define GET_QWORD_BE(data, offset) *(uint64_t *)((char *)(data) + (offset))
#define PUT_QWORD_BE(data, offset, value) *(uint64_t *)((char *)(data) + (offset)) = (value)
#endif

#endif
