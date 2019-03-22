# undefined = use OpenSSL
# 1 = use included sources
#CORECRYPTO = 1

# Darwin can use CommonCrypto instead of OpenSSL
#COMMONCRYPTO = 1

CC = gcc
CFLAGS = -Wall -W -pedantic
CFLAGS += -Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter
CFLAGS += -O2 -I. -g -DiOS10 -Ilzfse/src
CFLAGS += -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8
CFLAGS += -D__unused="__attribute__((unused))"

LD = gcc
LDFLAGS = -g -Llzfse/build/bin
LDLIBS = -llzfse

SOURCES = \
	lzss.c \
	img4.c

VFSSOURCES = \
	libvfs/vfs_file.c \
	libvfs/vfs_mem.c \
	libvfs/vfs_sub.c \
	libvfs/vfs_enc.c \
	libvfs/vfs_lzss.c \
	libvfs/vfs_lzfse.c \
	libvfs/vfs_img4.c

DERSOURCES = \
	libDER/DER_Encode.c \
	libDER/DER_Decode.c \
	libDER/oids.c

CCSOURCES = \
	corecrypto/arm/ccn_add.s \
	corecrypto/arm/ccn_addmul1.s \
	corecrypto/arm/ccn_cmp-arm64.s \
	corecrypto/arm/ccn_cmp.s \
	corecrypto/arm/ccn_mul.s \
	corecrypto/arm/ccn_mul1.s \
	corecrypto/arm/ccn_n-arm64.s \
	corecrypto/arm/ccn_n.s \
	corecrypto/arm/ccn_set.s \
	corecrypto/arm/ccn_sub.s \
	corecrypto/intel/ccn_add.s \
	corecrypto/intel/ccn_cmp-x86_64.s \
	corecrypto/intel/ccn_mul.s \
	corecrypto/intel/ccn_n-x86_64.s \
	corecrypto/intel/ccn_sub.s \
	corecrypto/cc_clear.c \
	corecrypto/cc_cmp_safe.c \
	corecrypto/ccaes_cbc_decrypt_mode.c \
	corecrypto/ccaes_cbc_encrypt_mode.c \
	corecrypto/gladman/aescrypt.c \
	corecrypto/gladman/aeskey.c \
	corecrypto/gladman/aestab.c \
	corecrypto/gladman/ccaes_gladman_cbc_decrypt.c \
	corecrypto/gladman/ccaes_gladman_cbc_encrypt.c \
	corecrypto/arm/aesdata.s \
	corecrypto/arm/aesdecbc.s \
	corecrypto/arm/aesencbc.s \
	corecrypto/arm/aeskey.s \
	corecrypto/arm/ccaes_arm_cbc_decrypt_mode.c \
	corecrypto/arm/ccaes_arm_cbc_encrypt_mode.c \
	corecrypto/ccdigest.c \
	corecrypto/ccdigest_final_64be.c \
	corecrypto/ccdigest_init.c \
	corecrypto/ccdigest_update.c \
	corecrypto/ccn_add.c \
	corecrypto/ccn_bitlen.c \
	corecrypto/ccn_cmp.c \
	corecrypto/ccn_mul.c \
	corecrypto/ccn_n.c \
	corecrypto/ccn_read_uint.c \
	corecrypto/ccn_set.c \
	corecrypto/ccn_shift_right.c \
	corecrypto/ccn_shift_right_multi.c \
	corecrypto/ccn_sqr.c \
	corecrypto/ccn_sub.c \
	corecrypto/ccn_write_uint.c \
	corecrypto/ccrsa_emsa_pkcs1v15_verify.c \
	corecrypto/ccrsa_pub_crypt.c \
	corecrypto/ccrsa_verify_pkcs1v15.c \
	corecrypto/ccsha1_initial_state.c \
	corecrypto/ccsha1_ltc.c \
	corecrypto/cczp_init.c \
	corecrypto/cczp_mod.c \
	corecrypto/cczp_mul.c \
	corecrypto/cczp_power_fast.c \
	corecrypto/cczp_sqr.c

OBJECTS = $(SOURCES:.c=.o) $(DERSOURCES:.c=.o) $(VFSSOURCES:.c=.o)
CCOBJECTS = $(addsuffix .o,$(basename $(CCSOURCES)))

ifdef CORECRYPTO
CC = clang
CFLAGS += -Wno-gnu -DUSE_CORECRYPTO #-DIBOOT=1
#CFLAGS += -DNO_CCZP_OPTIONS	# either way
OBJECTS += $(CCOBJECTS)
else
ifdef COMMONCRYPTO
CC = clang
CFLAGS += -DUSE_COMMONCRYPTO=1
LDLIBS += -framework Security -framework CoreFoundation
else
CFLAGS += -Wno-deprecated-declarations
LDLIBS += -lcrypto
endif
endif

.c.o:
	$(CC) -o $@ $(CFLAGS) -c $<
.s.o:
	$(CC) -o $@ $(CFLAGS) -x assembler-with-cpp -c $<

all: img4

img4: $(OBJECTS)
	$(LD) -o $@ $(LDFLAGS) $^ $(LDLIBS)

clean:
	-$(RM) $(OBJECTS) $(CCOBJECTS)

distclean: clean
	-$(RM) img4
