/*
 * img4 tool
 * xerub 2015, 2017
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef USE_CORECRYPTO
#   include <corecrypto/ccrsa.h>
#   include <corecrypto/ccsha1.h>
#elif USE_COMMONCRYPTO
#   include <CommonCrypto/CommonCrypto.h>
#else
#   include <openssl/bn.h>
#   include <openssl/err.h>
#   include <openssl/evp.h>
#   include <openssl/rsa.h>
#   include <openssl/sha.h>
#endif
#include <libDER/DER_Encode.h>
#include <libDER/DER_Decode.h>
#include <libDER/asn1Types.h>
#include <libDER/oids.h>
#include "validate_ca.h"

#define E000000000000000 (ASN1_CONSTRUCTED | ASN1_PRIVATE)

#define IS_EQUAL(a, b) ((a).length == (b).length && !memcmp((a).data, (b).data, (a).length))

#define FOURCC(tag) (unsigned char)((tag) >> 24), (unsigned char)((tag) >> 16), (unsigned char)((tag) >> 8), (unsigned char)(tag)

#define RESERVE_DIGEST_SPACE 20

#define panic(fn, args...) do { fprintf(stderr, fn args); exit(1); } while (0)

#ifdef iOS10
#include "lzfse.h"
#endif

typedef enum {
    DictMANP,
    DictOBJP
} DictType;

typedef struct {
    DERItem item;
    DERTag tag;
} DERMonster;

typedef struct {
    DERItem magic;      // "IM4P"
    DERItem type;       // "illb"
    DERItem version;    // "iBoot-2261.3.33"
    DERItem imageData;
    DERItem keybag;
#ifdef iOS10
    DERItem compression;
#endif
    DERByte full_digest[RESERVE_DIGEST_SPACE];
} TheImg4Payload;

typedef struct {
    DERItem magic;      // "IM4M"
    DERItem version;    // 0
    DERItem theset;     // MANB + MANP
    DERItem sig_blob;   // RSA
    DERItem chain_blob; // cert chain
    DERItem img4_blob;
    DERByte full_digest[RESERVE_DIGEST_SPACE];
    DERByte theset_digest[RESERVE_DIGEST_SPACE];
} TheImg4Manifest;

typedef struct {
    DERItem magic;      // "IM4R"
    DERItem nonce;
} TheImg4RestoreInfo;

typedef struct {
    bool payloadHashed;
    bool manifestHashed;
    DERItem payloadRaw;
    DERItem manifestRaw;
    DERItem manb;
    DERItem manp;
    DERItem objp;
    TheImg4Payload payload;
    TheImg4Manifest manifest;
    TheImg4RestoreInfo restoreInfo;
} TheImg4;

const DERItemSpec DERImg4ItemSpecs[4] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IMG4"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_ENC_WRITE_DER|DER_DEC_SAVE_DER },     // SEQUENCE(payload)
    { 2 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },     // CONS(SEQUENCE(manifest))
    { 3 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 1,  DER_DEC_OPTIONAL }      // CONS(SEQUENCE(restoreInfo))
};

#ifdef iOS10
const DERItemSpec DERImg4PayloadItemSpecs[6] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4P"
    { 1 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "illb"
    { 2 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "iBoot-2261.3.33"
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // binary data
    { 4 * sizeof(DERItem), ASN1_OCTET_STRING,                           DER_DEC_OPTIONAL },     // keybag
    { 5 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_ENC_WRITE_DER|DER_DEC_OPTIONAL }      // iOS10 compression info
};
#else
const DERItemSpec DERImg4PayloadItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4P"
    { 1 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "illb"
    { 2 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "iBoot-2261.3.33"
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // binary data
    { 4 * sizeof(DERItem), ASN1_OCTET_STRING,                           DER_DEC_OPTIONAL }      // keybag
};
#endif

const DERItemSpec DERImg4ManifestItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4M"
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },                    // 0
    { 2 * sizeof(DERItem), ASN1_CONSTR_SET,                             DER_DEC_SAVE_DER },     // SET(things)
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // RSA
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 }                     // chain
};

const DERItemSpec DERImg4RestoreInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4R"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SET,                             0 }                     // SET(nonce)
};

const DERItemSpec DERSignedCertCrlItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_DEC_SAVE_DER },
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 2 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERTBSCertItemSpecs[10] = {
    { 0 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },
    { 2 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 3 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 5 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 6 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 7 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 1,                   DER_DEC_OPTIONAL },
    { 8 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 2,                   DER_DEC_OPTIONAL },
    { 9 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 3,  DER_DEC_OPTIONAL }
};

const DERItemSpec DERAttributeTypeAndValueItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERExtensionItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), ASN1_BOOLEAN,                                DER_DEC_OPTIONAL },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 }
};

const DERItemSpec DERAlgorithmIdItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_OPTIONAL | DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERSubjPubKeyInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 1 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERRSAPubKeyPKCS1ItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,                                0x100 },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0x100 }
};

const DERByte _oidAppleImg4ManifestCertSpec[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 6, 1, 0xF };
const DERItem oidAppleImg4ManifestCertSpec = { (DERByte *)_oidAppleImg4ManifestCertSpec, sizeof(_oidAppleImg4ManifestCertSpec) };

const DERItem AppleSecureBootCA = { (DERByte *)"\x13)Apple Secure Boot Certification Authority", 0x2B };

const DERItemSpec kbagSpecs[] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,                                0 },
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },
};

/*****************************************************************************/

int
DERImg4DecodeFindInSequence(unsigned char *a1, unsigned char *a2, DERTag tag, DERItem *a5)
{
    DERDecodedInfo currDecoded;
    DERSequence derSeq;

    derSeq.nextItem = a1;
    derSeq.end = a2;

    do {
        int rv = DERDecodeSeqNext(&derSeq, &currDecoded);
        if (rv) {
            return rv;
        }
    } while (currDecoded.tag != tag);

    *a5 = currDecoded.content;
    return 0;
}

int
DERImg4DecodeContentFindItemWithTag(const DERItem *a1, DERTag tag, DERItem *a4)
{
    int rv;
    DERSequence derSeq;

    rv = DERDecodeSeqContentInit(a1, &derSeq);
    if (rv) {
        return rv;
    }
    return DERImg4DecodeFindInSequence(derSeq.nextItem, derSeq.end, tag, a4);
}

int
DERImg4DecodeTagCompare(const DERItem *a1, uint32_t nameTag)
{
    uint32_t var_14;

    if (a1->length < 4) {
        return -1;
    }
    if (a1->length > 4) {
        return 1;
    }

    if (DERParseInteger(a1, &var_14)) {
        return -2;
    }

    if (var_14 < nameTag) {
        return -1;
    }
    if (var_14 > nameTag) {
        return 1;
    }
    return 0;
}

int
DERImg4Decode(const DERItem *a1, DERItem *a2)
{
    int rv;
    DERDecodedInfo var_38;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeItem(a1, &var_38);
    if (rv) {
        return rv;
    }

    if (var_38.tag != ASN1_CONSTR_SEQUENCE) {
        return DR_UnexpectedTag;
    }

    if (a1->data + a1->length != var_38.content.data + var_38.content.length) {
        return DR_BufOverflow;
    }

    rv = DERParseSequenceContent(&var_38.content, 4, DERImg4ItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(a2, 'IMG4')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodePayload(const DERItem *a1, TheImg4Payload *a2)
{
    int rv;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

#ifdef iOS10
    rv = DERParseSequence(a1, 6, DERImg4PayloadItemSpecs, a2, 0);
#else
    rv = DERParseSequence(a1, 5, DERImg4PayloadItemSpecs, a2, 0);
#endif
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4P')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodeManifest(const DERItem *a1, TheImg4Manifest *a2)
{
    int rv;
    uint32_t var_14;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 5, DERImg4ManifestItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4M')) {
        return DR_UnexpectedTag;
    }

    rv = DERParseInteger(&a2->version, &var_14);
    if (rv) {
        return rv;
    }

    if (var_14) {
        return DR_UnexpectedTag;
    }
    return 0;
}

int
DERImg4DecodeRestoreInfo(const DERItem *a1, TheImg4RestoreInfo *a2)
{
    int rv;

    if (a1 == NULL) {
        return 0;
    }
    if (a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 2, DERImg4RestoreInfoItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4R')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodeFindProperty(const DERItem *a1, DERTag etag, DERTag atag, DERMonster *dest)
{
    int rv;
    DERItemSpec var_70[2];
    uint32_t var_3C;
    DERItem var_38;

    rv = DERImg4DecodeContentFindItemWithTag(a1, etag, &var_38);
    if (rv) {
        return rv;
    }

    var_70[0].offset = 0;
    var_70[0].tag = ASN1_IA5_STRING;
    var_70[0].options = 0;
    var_70[1].offset = sizeof(DERMonster);
    var_70[1].tag = atag;
    var_70[1].options = 0;

    rv = DERParseSequence(&var_38, 2, var_70, dest, 0);
    if (rv) {
        return rv;
    }

    rv = DERParseInteger(&dest[0].item, &var_3C);
    if (rv) {
        return rv;
    }

    if ((E000000000000000 | var_3C) != etag) {
        return DR_UnexpectedTag;
    }

    dest[0].tag = etag | E000000000000000;
    dest[1].tag = atag;
    return 0;
}

int
Img4DecodeGetPayload(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.imageData;
    return 0;
}

int
Img4DecodeGetPayloadType(TheImg4 *img4, unsigned int *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    return DERParseInteger(&img4->payload.type, a2);
}

int
Img4DecodeGetPayloadKeybag(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.keybag;
    return 0;
}

int
Img4DecodeManifestExists(TheImg4 *img4, bool *exists)
{
    if (img4 == NULL || exists == NULL) {
        return DR_ParamErr;
    }
    *exists = (img4->manifestRaw.data != NULL);
    return 0;
}

int
Img4DecodeGetRestoreInfoNonce(TheImg4 *img4, DERTag etag, DERTag atag, DERMonster *dest)
{
    if (img4 == NULL || dest == NULL) {
        return DR_ParamErr;
    }
    if (img4->restoreInfo.nonce.data == NULL || img4->restoreInfo.nonce.length == 0) {
        return 0;
    }
    return DERImg4DecodeFindProperty(&img4->restoreInfo.nonce, etag, atag, dest);
}

int
Img4DecodeGetRestoreInfoData(TheImg4 *img4, DERTag tag, DERByte **a4, DERSize *a5)
{
    int rv;
    DERMonster var_40[2];

    if (img4 == NULL || a4 == NULL || a5 == NULL) {
        return DR_ParamErr;
    }
    rv = Img4DecodeGetRestoreInfoNonce(img4, E000000000000000 | tag, ASN1_OCTET_STRING, var_40);
    if (rv) {
        return rv;
    }
    *a4 = var_40[1].item.data;
    *a5 = var_40[1].item.length;
    return 0;
}

int
Img4DecodeInit(DERByte *data, DERSize length, TheImg4 *img4)
{
    int rv;
    DERItem var_70[4];
    DERItem var_30;

    if (data == NULL || img4 == NULL) {
        return DR_ParamErr;
    }

    var_30.data = data;
    var_30.length = length;

    memset(var_70, 0, sizeof(var_70));
    memset(img4, 0, sizeof(TheImg4));

    rv = DERImg4Decode(&var_30, var_70);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodePayload(&var_70[1], &img4->payload);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeManifest(&var_70[2], &img4->manifest);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeRestoreInfo(&var_70[3], &img4->restoreInfo);
    if (rv) {
        return rv;
    }

    img4->payloadRaw = var_70[1];
    img4->manifestRaw = var_70[2];
    return 0;
}

#include <errno.h>
#include <fcntl.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccaes.h>
#elif !USE_COMMONCRYPTO
#include <openssl/aes.h>
#endif
#include "libvfs/vfs.h"
#include "libvfs/vfs_internal.h"

struct file_ops_img4 {
    struct file_ops ops;
    FHANDLE pfd;
    FHANDLE other;
    DERItem manifest;
    DERItem keybag;
    DERItem version;
    uint64_t nonce;
    unsigned type;
    int hasnonce;
    int wasimg4;
    int lzfse;
    int dirty;
};

const DERItemSpec nonceItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "BNCN"
    { 1 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 }                     // nonce
};

static TheImg4 *
parse(unsigned char *data, unsigned length)
{
    int rv;
    TheImg4 *img4;

    img4 = malloc(sizeof(TheImg4));
    if (!img4) {
        return NULL;
    }
    memset(img4, 0, sizeof(TheImg4));

    rv = Img4DecodeInit(data, length, img4);
    if (rv) {
        DERItem item;
        item.data = data;
        item.length = length;
        rv = DERImg4DecodePayload(&item, &img4->payload);
    }
    if (rv) {
        free(img4);
        return NULL;
    }

    return img4;
}

static int
derdup(DERItem *dst, DERItem *src)
{
    void *ptr = NULL;
    DERSize length = src->length;
    if (length && src->data) {
        ptr = malloc(length);
        if (!ptr) {
            return -1;
        }
        memcpy(ptr, src->data, length);
    }
    dst->data = ptr;
    dst->length = length;
    return 0;
}

static DERReturn
aDEREncodeItem(DERItem *item, DERTag tag, DERSize length, DERByte *src, bool freeOld)
{
    DERReturn rv;
    DERByte *old = freeOld ? src : NULL;
    DERSize inOutLen = DER_MAX_ENCODED_SIZE(length);
    DERByte *der = malloc(inOutLen);
    if (!der) {
        free(old);
        return -1;
    }

    rv = DEREncodeItem(tag, length, src, der, &inOutLen);
    free(old);
    if (rv) {
        free(der);
        return rv;
    }

    item->data = der;
    item->length = inOutLen;
    return 0;
}

static DERReturn
aDEREncodeSequence(DERItem *where, DERTag topTag, const void *src, DERShort numItems, const DERItemSpec *itemSpecs, int freeElt)
{
    int i;
    DERReturn rv;
    DERByte *der;
    DERSize inOutLen;
    DERByte *old = NULL;

    inOutLen = 1000; // XXX blah
    for (i = numItems - 1; i >= 0; i--) {
        const DERItem *item = (DERItem *)((char *)src + itemSpecs[i].offset);
        inOutLen += DER_MAX_ENCODED_SIZE(item->length);
        if (i == freeElt) {
            old = item->data;
        }
    }
    der = malloc(inOutLen);
    if (!der) {
        free(old);
        return -1;
    }

    rv = DEREncodeSequence(topTag, src, numItems, itemSpecs, der, &inOutLen);
    free(old);
    if (rv) {
        free(der);
        return rv;
    }

    where->data = der;
    where->length = inOutLen;
    return 0;
}

static int
makePayload(DERItem *where, unsigned type, DERItem *version, DERItem *keybag, DERItem *compr, unsigned char *data, size_t size)
{
    char IM4P[] = "IM4P";
    DERByte tmp[4];
    DERItem elements[6];
    int n = 5;

    PUT_DWORD_BE(tmp, 0, type);

    elements[0].data = (DERByte *)IM4P;
    elements[0].length = sizeof(IM4P) - 1;
    elements[1].data = tmp;
    elements[1].length = 4;
    elements[2] = *version;
    elements[3].data = data;
    elements[3].length = size;
    if (keybag && keybag->data && keybag->length) {
        elements[4] = *keybag;
    } else {
        elements[4].data = NULL;
        elements[4].length = 0;
    }
#ifdef iOS10
    if (compr && compr->data && compr->length) {
        elements[5] = *compr;
        n++;
    }
#endif
    return aDEREncodeSequence(where, ASN1_CONSTR_SEQUENCE, elements, n, DERImg4PayloadItemSpecs, -1);
}

static int
makeRestoreInfo(DERItem *where, uint64_t nonce)
{
    int rv;
    char IM4R[] = "IM4R";
    char BNCN[] = "BNCN";
    unsigned char tmp[8];

    DERItem item;
    DERItem elements[2];
    DERItem restoreInfo[2];

    PUT_QWORD_BE(tmp, 0, nonce);

    elements[0].data = (DERByte *)BNCN;
    elements[0].length = sizeof(BNCN) - 1;
    elements[1].data = tmp;
    elements[1].length = 8;

    rv = aDEREncodeSequence(&item, ASN1_CONSTR_SEQUENCE, elements, 2, nonceItemSpecs, -1);
    if (rv) {
        return rv;
    }

    rv = aDEREncodeItem(restoreInfo + 1, ASN1_CONSTRUCTED | ASN1_PRIVATE | 'BNCN', item.length, item.data, true);
    if (rv) {
        return rv;
    }

    restoreInfo[0].data = (DERByte *)IM4R;
    restoreInfo[0].length = sizeof(IM4R) - 1;

    return aDEREncodeSequence(where, ASN1_CONSTR_SEQUENCE, restoreInfo, 2, DERImg4RestoreInfoItemSpecs, 1);
}

static int
makeCompression(DERItem *where, uint32_t deco, size_t size)
{
    unsigned char *p;
    unsigned char dbytes[5];
    unsigned char sbytes[9];
    DERItem elements[2];

    /* XXX we can skip 0x80 test only because DER_ENC_SIGNED_INT */

    *dbytes = 0;
    PUT_DWORD_BE(dbytes, 1, deco);
    for (p = dbytes; p < dbytes + 4 && !(p[0] /*|| (p[1] & 0x80)*/); p++) {
        continue;
    }
    elements[0].data = p;
    elements[0].length = dbytes + sizeof(dbytes) - p;

    *sbytes = 0;
    PUT_QWORD_BE(sbytes, 1, size);
    for (p = sbytes; p < sbytes + 8 && !(p[0] /*|| (p[1] & 0x80)*/); p++) {
        continue;
    }
    elements[1].data = p;
    elements[1].length = sbytes + sizeof(sbytes) - p;

    /* XXX ugly hack: reuse DERRSAPubKeyPKCS1ItemSpecs */
    return aDEREncodeSequence(where, ASN1_CONSTR_SEQUENCE, elements, 2, DERRSAPubKeyPKCS1ItemSpecs, -1);
}

static int
reassemble(struct file_ops_img4 *fd, DERItem *out)
{
    int rv;
    void *data;
    size_t size;
    DERItem items[4];
    DERItem compr = { NULL, 0 };
    char IMG4[] = "IMG4";
    FHANDLE pfd = fd->pfd;

    rv = pfd->ioctl(pfd, IOCTL_MEM_GET_BACKING, &data, &size);
    if (rv) {
        return rv;
    }
    if (fd->lzfse) {
        rv = makeCompression(&compr, fd->lzfse, pfd->length(pfd));
        if (rv) {
            return rv;
        }
    }
    rv = makePayload(&items[1], fd->type, &fd->version, &fd->keybag, &compr, data, size);
    free(compr.data);
    if (rv) {
        return rv;
    }
    items[0].data = (DERByte *)IMG4;
    items[0].length = sizeof(IMG4) - 1;
    if (fd->manifest.data) {
        int n = 3;
        items[2] = fd->manifest;
        if (fd->hasnonce) {
            rv = makeRestoreInfo(&items[3], fd->nonce);
            if (rv) {
                free(items[1].data);
                return rv;
            }
            n++;
        }
        rv = aDEREncodeSequence(out, ASN1_CONSTR_SEQUENCE, items, n, DERImg4ItemSpecs, 3);
        free(items[1].data);
    } else if (fd->wasimg4) {
        rv = aDEREncodeSequence(out, ASN1_CONSTR_SEQUENCE, items, 2, DERImg4ItemSpecs, 1);
    } else {
        *out = items[1];
    }
    if (rv) {
        free(out->data);
    }
    return rv;
}

static unsigned long long
getint(const char *s, size_t len, unsigned long long def)
{
    unsigned long long val;
    char *bp;
    errno = 0;
    val = strtoull(s, &bp, 0);
    if (errno == 0 && bp == s + len) {
        return val;
    }
    return def;
}

static void
parseargs(const char *s)
{
    do {
        size_t index = strcspn(s, " \t,\r\n");
        if (index) {
            const char *p = memchr(s, '=', index);
            if (p && p - s == 4) {
                size_t vallen = s + index - ++p;
                getint(p, vallen, -1);
            }
        }
        s += index;
        s += strspn(s, " \t,\r\n");
    } while (*s);
}

static int
validate(TheImg4 *img4, unsigned type, const char *args)
{
    /* XXX TODO */
    parseargs(args);
    return -1;
}

static int
dovalidate(struct file_ops_img4 *fd, const char *args)
{
    int rv;
    DERItem out;
    TheImg4 *img4;
    FHANDLE pfd = fd->pfd;

    rv = pfd->fsync(pfd);
    if (rv) {
        return -1;
    }

    rv = reassemble(fd, &out);
    if (rv) {
        return rv;
    }

    img4 = parse(out.data, out.length);
    if (!img4) {
        free(out.data);
        return -1;
    }

    rv = validate(img4, fd->type, args);
#if !defined(USE_CORECRYPTO) && !USE_COMMONCRYPTO
    EVP_cleanup();
    ERR_remove_state(0);
    CRYPTO_cleanup_all_ex_data();
#endif

    free(img4);
    free(out.data);
    return rv;
}

static int
img4_fsync(FHANDLE fd_)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    int rv;
    DERItem out;
    size_t size;
    FHANDLE pfd;
    FHANDLE other;

    if (!fd) {
        return -1;
    }
    pfd = fd->pfd;
    if (pfd->flags == O_RDONLY) {
        return 0;
    }
    rv = pfd->fsync(pfd);
    if (rv) {
        return -1;
    }
    other = fd->other;
    fd->dirty = 1; /* XXX TODO: this should be set iff pfd *was* dirty */
    if (!fd->dirty) {
        goto next;
    }

    rv = reassemble(fd, &out);
    if (rv) {
        return rv;
    }

    other->lseek(other, 0, SEEK_SET);
    size = other->write(other, out.data, out.length);
    free(out.data);
    if (size != out.length) {
        return -1;
    }

    other->ftruncate(other, out.length);
  next:
    fd->dirty = 0;
    return other->fsync(other);
}

static int
img4_close(FHANDLE fd)
{
    struct file_ops_img4 *ctx = (struct file_ops_img4 *)fd;
    FHANDLE pfd;
    FHANDLE other;
    int rv, rc;
    if (!fd) {
        return -1;
    }
    pfd = ctx->pfd;
    other = ctx->other;
    rv = fd->fsync(fd);
    free(ctx->manifest.data);
    free(ctx->keybag.data);
    free(ctx->version.data);
    free(fd);
    rc = pfd->close(pfd);
    rc = other->close(other); /* XXX ugh?... which code to keep? */
    return rv ? rv : rc;
}

static ssize_t
img4_read(FHANDLE fd_, void *buf, size_t count)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->pfd->read(fd->pfd, buf, count);
}

static ssize_t
img4_write(FHANDLE fd_, const void *buf, size_t count)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->pfd->write(fd->pfd, buf, count);
}

static off_t
img4_lseek(FHANDLE fd_, off_t offset, int whence)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->pfd->lseek(fd->pfd, offset, whence);
}

static int
img4_ioctl(FHANDLE fd, unsigned long req, ...)
{
    struct file_ops_img4 *ctx = (struct file_ops_img4 *)fd;
    int rv = -1;
    va_list ap;

    if (!fd) {
        return -1;
    }

    va_start(ap, req);
    switch (req) {
        case IOCTL_IMG4_EVAL_TRUST: {
            void *param = va_arg(ap, void *);
            rv = dovalidate(ctx, param);
            break;
        }
        case IOCTL_IMG4_GET_KEYBAG: {
            void **dst = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *dst = ctx->keybag.data;
            *sz = ctx->keybag.length;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_GET_KEYBAG2: {
            unsigned i;
            DERTag tag;
            DERSequence seq;
            DERDecodedInfo info;
            if (DERDecodeSeqInit(&ctx->keybag, &tag, &seq)) {
                break;
            }
            if (tag != ASN1_CONSTR_SEQUENCE) {
                break;
            }
            for (i = 0; !DERDecodeSeqNext(&seq, &info); i++) {
                DERItem items[3];
                if (info.tag != ASN1_CONSTR_SEQUENCE) {
                    break;
                }
                if (DERParseSequenceContent(&info.content, 3, kbagSpecs, items, 3 * sizeof(DERItem))) {
                    break;
                }
                if (items[1].length != 16 || items[2].length != 32) {
                    break;
                }
                if (i < 2) {
                    unsigned char *kbag = va_arg(ap, unsigned char *);
                    memcpy(kbag, items[1].data, 16);
                    memcpy(kbag + 16, items[2].data, 32);
                }
            }
            if (i == 2) {
                rv = 0;
            }
            break;
        }
        case IOCTL_IMG4_GET_TYPE: {
            unsigned *type = va_arg(ap, unsigned *);
            *type = ctx->type;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_SET_TYPE: {
            unsigned type = va_arg(ap, unsigned);
            ctx->type = type;
            ctx->dirty = 1;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_GET_MANIFEST: {
            void **dst = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *dst = ctx->manifest.data;
            *sz = ctx->manifest.length;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_SET_MANIFEST: if (fd->flags == O_RDONLY) break; else {
            DERItem item;
            TheImg4Manifest tmp;
            void *old = ctx->manifest.data;
            item.data = va_arg(ap, void *);
            item.length = va_arg(ap, size_t);
            rv = DERImg4DecodeManifest(&item, &tmp);
            if (rv) {
                break;
            }
            rv = derdup(&ctx->manifest, &item);
            if (rv) {
                break;
            }
            free(old);
            ctx->dirty = 1;
            break;
        }
        case IOCTL_IMG4_GET_NONCE: {
            uint64_t *ptr = va_arg(ap, uint64_t *);
            if (!ctx->hasnonce) {
                break;
            }
            *ptr = ctx->nonce;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_SET_NONCE: if (fd->flags == O_RDONLY) break; else {
            ctx->nonce = va_arg(ap, uint64_t);
            ctx->hasnonce = 1;
            ctx->dirty = 1;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_GET_VERSION: {
            void **dst = va_arg(ap, void **);
            size_t *sz = va_arg(ap, size_t *);
            *dst = ctx->version.data;
            *sz = ctx->version.length;
            rv = 0;
            break;
        }
        case IOCTL_IMG4_SET_VERSION: if (fd->flags == O_RDONLY) break; else {
            DERItem item;
            void *old = ctx->version.data;
            item.data = va_arg(ap, void *);
            item.length = va_arg(ap, size_t);
            rv = derdup(&ctx->version, &item);
            if (rv) {
                break;
            }
            free(old);
            ctx->dirty = 1;
            break;
        }
        case IOCTL_ENC_SET_NOENC: if (fd->flags == O_RDONLY) break; else {
            FHANDLE pfd = ctx->pfd;
            pfd->ioctl(pfd, req); /* may fail if enc is just a pass-through */
            free(ctx->keybag.data);
            ctx->keybag.data = NULL;
            ctx->keybag.length = 0;
            ctx->dirty = 1;
            rv = 0;
            break;
        }
        case IOCTL_LZFSE_SET_LZSS: if (fd->flags == O_RDONLY) break; else {
            if (ctx->lzfse) {
                FHANDLE pfd = ctx->pfd;
                rv = pfd->ioctl(pfd, req);
                if (rv == 0) {
                    ctx->lzfse = 0;
                    ctx->dirty = 1;
                }
            }
            break;
        }
        default: {
            void *a = va_arg(ap, void *);
            void *b = va_arg(ap, void *);
            FHANDLE pfd = ctx->pfd;
            rv = pfd->ioctl(pfd, req, a, b); /* XXX varargs */
        }
    }
    va_end(ap);
    return rv;
}

static int
img4_ftruncate(FHANDLE fd_, off_t length)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->pfd->ftruncate(fd->pfd, length);
}

static ssize_t
img4_length(FHANDLE fd_)
{
    struct file_ops_img4 *fd = (struct file_ops_img4 *)fd_;
    if (!fd) {
        return -1;
    }
    return fd->pfd->length(fd->pfd);
}

FHANDLE
img4_reopen(FHANDLE other, const unsigned char *ivkey)
{
    int rv;
    struct file_ops_img4 *ops, *ctx;
    size_t n, total;
    unsigned char *buf;
    TheImg4 *img4;
    DERItem item;
    bool exists = false;
    FHANDLE pfd;
    unsigned char *dup;
    unsigned type;
    uint32_t deco = 0;
    DERByte *der;
    DERSize derlen;

    if (!other) {
        return NULL;
    }
    if (other->flags == O_WRONLY) {
        goto closeit;
    }

    total = other->length(other);
    if ((ssize_t)total < 0) {
        goto closeit;
    }
    buf = malloc(total);
    if (!buf) {
        goto closeit;
    }

    n = other->read(other, buf, total);
    if (n != total) {
        goto freebuf;
    }

    img4 = parse(buf, total);
    if (!img4) {
        goto freebuf;
    }

    rv = Img4DecodeGetPayload(img4, &item);
    if (rv) {
        fprintf(stderr, "[e] cannot extract payload\n");
        goto freeimg;
    }
    rv = Img4DecodeGetPayloadType(img4, &type);
    if (rv) {
        fprintf(stderr, "[e] cannot identify\n");
        goto freeimg;
    }

    dup = calloc(1, item.length);
    if (!dup) {
        goto freeimg;
    }
    memcpy(dup, item.data, item.length);

    pfd = memory_open(other->flags, dup, item.length);
    if (!pfd) {
        free(dup);
    }
    if (ivkey) {
        rv = Img4DecodeGetPayloadKeybag(img4, &item);
        if (rv || item.length == 0) {
            fprintf(stderr, "[w] image has no keybag\n");
        } else {
            pfd = enc_reopen(pfd, ivkey, ivkey + 16);
        }
    }
#ifdef iOS10
    if (img4->payload.compression.data && img4->payload.compression.length) {
        DERItem tmp[2];
        uint64_t usize = 0;
        if (DERParseSequenceContent(&img4->payload.compression, 2, DERRSAPubKeyPKCS1ItemSpecs, tmp, 0) ||
            DERParseInteger(&tmp[0], &deco) || DERParseInteger64(&tmp[1], &usize)) {
            fprintf(stderr, "[W] cannot get decompression info\n");
        }
        if (deco == 1) {
            pfd = lzfse_reopen(pfd, usize);
        }
    } else
#endif
    pfd = lzss_reopen(pfd);
    if (!pfd) {
        goto freeimg;
    }

    ops = calloc(1, sizeof(struct file_ops_img4));
    if (!ops) {
        goto closefd;
    }
    ctx = ops;
    ctx->pfd = pfd;
    ctx->type = type;
    ctx->lzfse = deco;
    ctx->other = other;
    ctx->wasimg4 = (img4->payloadRaw.data != NULL);

    rv = Img4DecodeManifestExists(img4, &exists);
    if (rv == 0 && exists) {
        rv = derdup(&ctx->manifest, &img4->manifestRaw);
        if (rv) {
            goto freeops;
        }
    }
    rv = derdup(&ctx->keybag, &img4->payload.keybag);
    if (rv) {
        goto err1;
    }
    rv = derdup(&ctx->version, &img4->payload.version);
    if (rv) {
        goto err2;
    }

    if (img4->restoreInfo.nonce.data && img4->restoreInfo.nonce.length) {
        rv = Img4DecodeGetRestoreInfoData(img4, 'BNCN', &der, &derlen);
        if (rv == 0) {
            ctx->hasnonce = 1;
            ctx->nonce = GET_QWORD_BE(der, 0);
        }
    }

    free(img4);
    free(buf);

    ops->ops.read = img4_read;
    ops->ops.write = img4_write;
    ops->ops.lseek = img4_lseek;
    ops->ops.ioctl = img4_ioctl;
    ops->ops.ftruncate = img4_ftruncate;
    ops->ops.fsync = img4_fsync;
    ops->ops.close = img4_close;
    ops->ops.length = img4_length;
    ops->ops.flags = other->flags;
    return (FHANDLE)ops;

  err2:
    free(ctx->keybag.data);
  err1:
    free(ctx->manifest.data);
  freeops:
    free(ops);
  closefd:
    pfd->close(pfd);
  freeimg:
    free(img4);
  freebuf:
    free(buf);
  closeit:
    other->close(other);
    return NULL;
}
