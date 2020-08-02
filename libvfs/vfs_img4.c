/*
 * img4 tool
 * xerub 2015, 2017
 */


#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#elif defined(USE_COMMONCRYPTO)
#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecItem.h>
#include <Security/SecKey.h>
#else
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
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

typedef struct {
    uint64_t CHIP;
    uint64_t ECID;
    uint64_t SEPO;
    uint64_t SDOM;
    uint64_t BORD;
    unsigned char CPRO;
    unsigned char CSEC;
    unsigned char field_2A;
    unsigned char field_2B;
    unsigned char field_2C;
    unsigned char field_2D;
    unsigned char field_2E;
    unsigned char field_2F;
    uint64_t field_30;
    unsigned char boot_manifest_hash[20];
    unsigned char hashvalid;
    unsigned char field_4D;
    unsigned char field_4E;
    unsigned char field_4F;
} ContextH;

typedef struct {
    unsigned char field_0;
    unsigned char field_1;
    unsigned char field_2;
    unsigned char field_3;
    unsigned char field_4;
    unsigned char field_5;
    unsigned char field_6;
    unsigned char field_7;
    unsigned char manifest_hash[20];
    bool has_manifest;
    unsigned char field_1D;
    unsigned char payload_hash[20];
} ContextU;

typedef struct {
    TheImg4 *img4;
    ContextH *hardware;
    ContextU *unknown;
} CTX;

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

#define doHash sha1_digest

void
sha1_digest(const void *data, DERSize length, DERByte digest[20])
{
#ifdef USE_CORECRYPTO
    ccdigest(&ccsha1_ltc_di, length, data, digest);
#elif defined(USE_COMMONCRYPTO)
    CC_SHA1(data, length, digest);
#else
    SHA1(data, length, digest);
#endif
}

int
verify_signature_rsa(const DERItem *pkey, const DERItem *digest, const DERItem *sig)
{
    int rv;
#ifdef USE_CORECRYPTO
    const DERByte *ptr;
    DERSize len;
    cc_size n;

    bool valid;
    DERItem pkeyComponents[2];
    DERItem var_390;
    ccrsa_pub_ctx_decl(256, key);

    ccrsa_ctx_n(key) = 256;

    valid = false;

    var_390 = *pkey;

    if (DERParseSequence(&var_390, 2, DERRSAPubKeyPKCS1ItemSpecs, pkeyComponents, 2 * sizeof(DERItem))) {
        return -1;
    }

    len = pkeyComponents[0].length;
    ptr = pkeyComponents[0].data;

    while (len && *ptr == 0) {
        ptr++;
        len--;
    }

    n = ccn_nof_size(len);
    if (n > ccrsa_ctx_n(key)) {
        return -1;
    }
    ccrsa_ctx_n(key) = n;
    ccn_read_uint(n, ccrsa_ctx_m(key), len, ptr);
    cczp_init(ccrsa_ctx_zm(key));
    rv = ccn_read_uint(n, ccrsa_ctx_e(key), pkeyComponents[1].length, pkeyComponents[1].data);
    if (rv) {
        return -1;
    }
    rv = ccrsa_verify_pkcs1v15(key, ccoid_sha1, digest->length, digest->data, sig->length, sig->data, &valid);
    printf("+rv = %d, valid = %d\n", rv, valid);
    return (valid != true) | (rv != 0);
#elif defined(USE_COMMONCRYPTO)
    int bits = 256 * 8;
    CFNumberRef n;
    const void *keys[3];
    const void *values[3];
    CFDictionaryRef dict;
    CFErrorRef error = NULL;
    CFDataRef data, sigData;
    SecKeyRef k;

    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &bits);
    if (!n) {
        return -1;
    }

    keys[0] = kSecAttrKeyType;       values[0] = kSecAttrKeyTypeRSA;
    keys[1] = kSecAttrKeyClass;      values[1] = kSecAttrKeyClassPublic;
    keys[2] = kSecAttrKeySizeInBits; values[2] = n;
    dict = CFDictionaryCreate(NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(n);
    if (!dict) {
        return -1;
    }

    data = CFDataCreate(NULL, pkey->data, pkey->length);
    if (!data) {
        CFRelease(dict);
        return -1;
    }

    k = SecKeyCreateWithData(data, dict, &error);
    CFRelease(data);
    CFRelease(dict);
    if (!k) {
        return -1;
    }

    data = CFDataCreate(NULL, digest->data, digest->length);
    sigData = CFDataCreate(NULL, sig->data, sig->length);
    rv = (data && sigData) ? SecKeyVerifySignature(k, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1, data, sigData, &error) : 0;
    CFRelease(sigData);
    CFRelease(data);
    CFRelease(k);

    printf("+rv = %d\n", rv);
    return (rv == 1) ? 0 : -1;
#else
    RSA *rsa;
    DERItem pkeyComponents[2];

    if (DERParseSequence(pkey, 2, DERRSAPubKeyPKCS1ItemSpecs, pkeyComponents, 2 * sizeof(DERItem))) {
        return -1;
    }

    rsa = RSA_new();
    assert(rsa);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rv = RSA_set0_key(rsa, BN_bin2bn(pkeyComponents[0].data, pkeyComponents[0].length, NULL), BN_bin2bn(pkeyComponents[1].data, pkeyComponents[1].length, NULL), NULL);
    assert(rv == 1);
#else
    rsa->n = BN_bin2bn(pkeyComponents[0].data, pkeyComponents[0].length, NULL);
    assert(rsa->n);

    rsa->e = BN_bin2bn(pkeyComponents[1].data, pkeyComponents[1].length, NULL);
    assert(rsa->e);
#endif

    rv = RSA_verify(NID_sha1, digest->data, digest->length, sig->data, sig->length, rsa);
    printf("+rv = %d\n", rv);

    RSA_free(rsa);
    return (rv == 1) ? 0 : -1;
#endif
}

int
img4_verify_signature_with_chain(
    void *chain_blob_data, unsigned int chain_blob_length,
    void *sig_blob_data, unsigned int sig_blob_length,
    void *digest_data, unsigned int digest_length,
    DERByte **img4_data, DERSize *img4_length)
{
    DERItem var_540;
    DERItem var_530[3];
    DERItem var_500[3];
    DERItem var_4D0[3][10];
    DERItem var_2F0[3][3];
    DERItem certChain[3];       // var_260
    DERDecodedInfo var_230;
    DERItem var_218;
    DERItem var_208[2];
    unsigned char var_1E1;
    DERItem var_1E0[2];
    DERItem var_1C0[3];
    DERDecodedInfo var_190;
    DERTag var_178;
    DERSequence var_170;
    DERDecodedInfo var_160;
    DERItem var_148;
    DERItem var_138;
    unsigned char var_121;
    DERItem var_120[2];
    DERDecodedInfo var_100;
    DERSequence var_E8;
    DERItem var_D8[2];
    DERDecodedInfo var_B8;
    DERSequence var_A0;
    DERItem var_90;
    DERItem var_80;
    unsigned char var_6C[20];

    DERSize v1;
    unsigned i;
    int rv;

    certChain[0].data = (void *)ROOT_CA_CERTIFICATE;
    certChain[0].length = ROOT_CA_CERTIFICATE_SIZE;

    var_218.data = chain_blob_data;
    var_218.length = chain_blob_length;

    i = 1;
    do {
        if (DERDecodeItem(&var_218, &var_230)) {
            return -1;
        }
        v1 = var_230.content.data + var_230.content.length - var_218.data;
        if (v1 > var_218.length || i > 2) {
            return -1;
        }
        certChain[i].length = v1;
        certChain[i].data = var_218.data;
        i++;
        var_218.length -= v1;
        var_218.data += v1;
    } while (var_218.length);
    if (i != 3) {
        return -1;
    }

    for (i = 0; i < 3; i++) {
        if (DERParseSequence(&certChain[i], 3, DERSignedCertCrlItemSpecs, var_2F0[i], 3 * sizeof(DERItem))
            || DERParseSequence(var_2F0[i], 10, DERTBSCertItemSpecs, var_4D0[i], 10 * sizeof(DERItem))
            || DERParseSequenceContent(&var_4D0[i][6], 2, DERSubjPubKeyInfoItemSpecs, var_1E0, 2 * sizeof(DERItem))
            || DERParseSequenceContent(var_1E0, 2, DERAlgorithmIdItemSpecs, var_208, 2 * sizeof(DERItem))
            || !DEROidCompare(var_208, &oidRsa)) {
            return -1;
        }
        if (var_208[1].length) {
            if (var_208[1].length != 2 || var_208[1].data[0] != 5 || var_208[1].data[1]) {
                return -1;
            }
        }

        if (DERParseBitString(&var_1E0[1], &var_500[i], &var_1E1) || var_1E1) {
            return -1;
        }

        var_530[i].data = NULL;
        var_530[i].length = 0;
        if (var_4D0[i][9].length == 0) {
            continue;
        }
        if (DERDecodeSeqInit(&var_4D0[i][9], &var_178, &var_170)) {
            return -1;
        }
        if (var_178 != ASN1_CONSTR_SEQUENCE) {
            return -1;
        }
        while (!DERDecodeSeqNext(&var_170, &var_190)) {
            if (var_190.tag != ASN1_CONSTR_SEQUENCE || DERParseSequenceContent(&var_190.content, 3, DERExtensionItemSpecs, var_1C0, 3 * sizeof(DERItem))) {
                return -1;
            }
            if (DEROidCompare(&oidAppleImg4ManifestCertSpec, var_1C0)) {
                if (DERDecodeItem(&var_1C0[2], &var_160) || var_160.tag != ASN1_CONSTR_SET) {
                    return -1;
                }
                var_530[i] = var_1C0[2];
            }
        }
    }

    for (i = 1; i < 3; i++) {
        if (!IS_EQUAL(var_4D0[i - 1][5], var_4D0[i][3])) {
            return -1;
        }
        var_138.data = var_6C;
        var_138.length = 20;

        if (DERParseSequenceContent(&var_2F0[i][1], 2, DERAlgorithmIdItemSpecs, var_120, 2 * sizeof(DERItem))) {
            return -1;
        }
        if (!DEROidCompare(var_120, &oidSha1Rsa)) {
            return -1;
        }
        sha1_digest(var_2F0[i][0].data, var_2F0[i][0].length, var_6C); //ccdigest(ccsha1_ltc_di_copy, var_2F0[i][0].length, var_2F0[i][0].data, var_6C);
        if (DERParseBitString(&var_2F0[i][2], &var_148, &var_121) || var_121) {
            return -1;
        }
        if (verify_signature_rsa(&var_500[i - 1], &var_138, &var_148)) {
            return -1;
        }
    }

    var_540.data = NULL;
    var_540.length = 0;
    if (DERDecodeSeqContentInit(&var_4D0[1][5], &var_E8)) {
        return -1;
    }

    do {
        if (DERDecodeSeqNext(&var_E8, &var_100)) {
            return -1;
        }
        if (var_100.tag != ASN1_CONSTR_SET) {
            return -1;
        }
        rv = DERDecodeSeqContentInit(&var_100.content, &var_A0);
        if (rv) {
            rv = -1;
            continue;
        }
        while ((rv = DERDecodeSeqNext(&var_A0, &var_B8)) == DR_Success) {
            if (var_B8.tag != ASN1_CONSTR_SEQUENCE) {
                rv = -1;
                break;
            }
            if (DERParseSequenceContent(&var_B8.content, 2, DERAttributeTypeAndValueItemSpecs, var_D8, 2 * sizeof(DERItem))) {
                rv = -1;
                break;
            }
            if (DEROidCompare(&oidCommonName, var_D8)) {
                var_540 = var_D8[1];
                break;
            }
        }
    } while (rv == DR_EndOfSequence);

    if (rv) {
        return -1;
    }
    if (!DEROidCompare(&AppleSecureBootCA, &var_540)) {
        return -1;
    }
    var_80.data = sig_blob_data;
    var_80.length = sig_blob_length;
    var_90.data = digest_data;
    var_90.length = digest_length;
    if (digest_length != 20) {
        return -1;
    }
    if (verify_signature_rsa(&var_500[2], &var_90, &var_80)) {
        return -1;
    }
    if (var_530[2].data && var_530[2].length && img4_data && img4_length) {
        *img4_data = var_530[2].data;
        *img4_length = var_530[2].length;
    }
    return 0;
}

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
DERImg4DecodeProperty(const DERItem *a1, DERTag etag, DERMonster *a4)
{
    int rv;
    uint32_t var_6C;
    DERTag tag;
    DERSequence var_60;
    DERDecodedInfo var_50;
    DERDecodedInfo var_38;

    if (a1 == NULL || a4 == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeSeqInit(a1, &tag, &var_60);
    if (rv) {
        return rv;
    }

    if (tag != ASN1_CONSTR_SEQUENCE) {
        return DR_UnexpectedTag;
    }

    rv = DERDecodeSeqNext(&var_60, &var_38);
    if (rv) {
        return rv;
    }

    if (var_38.tag != ASN1_IA5_STRING) {
        return DR_UnexpectedTag;
    }

    rv = DERParseInteger(&var_38.content, &var_6C);
    if (rv) {
        return rv;
    }

    if ((E000000000000000 | var_6C) != etag) {
        return DR_UnexpectedTag;
    }

    a4[0].item = var_38.content;

    rv = DERDecodeSeqNext(&var_60, &var_50);
    if (rv) {
        return rv;
    }

    a4[1].tag = var_50.tag;
    a4[1].item = var_50.content;

    rv = DERDecodeSeqNext(&var_60, &var_50);
    if (rv != DR_EndOfSequence) {
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
Img4DecodeCopyPayloadHash(TheImg4 *img4, void *hash, DERSize length)
{
    unsigned char var_3C[20];

    if (img4 == NULL || hash == NULL || length != 20) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    if (!img4->payloadHashed) {
        sha1_digest(img4->payloadRaw.data, img4->payloadRaw.length, var_3C);
        memmove(hash, &var_3C, length);
        return 0;
    }
    if (length != 20) {
        return DR_BufOverflow;
    }
    memcpy(hash, img4->payload.full_digest, 20);
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
Img4DecodeCopyManifestHash(TheImg4 *img4, void *hash, DERSize length)
{
    unsigned char var_3C[20];

    if (img4 == NULL || hash == NULL || length != 20) {
        return DR_ParamErr;
    }
    if (img4->manifestRaw.data == NULL) {
        return DR_EndOfSequence;
    }
    if (!img4->manifestHashed) {
        sha1_digest(img4->manifestRaw.data, img4->manifestRaw.length, var_3C);
        memmove(hash, var_3C, length);
        return 0;
    }
    if (length != 20) {
        return DR_BufOverflow;
    }
    memcpy(hash, img4->manifest.full_digest, 20);
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
Img4DecodeGetPropertyInteger64(const DERItem *a1, DERTag tag, uint64_t *value)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_INTEGER) {
        return DR_UnexpectedTag;
    }

    return DERParseInteger64(&var_40[1].item, value);
}

int
Img4DecodeGetPropertyBoolean(const DERItem *a1, DERTag tag, bool *value)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_BOOLEAN) {
        return DR_UnexpectedTag;
    }

    return DERParseBoolean(&var_40[1].item, value);
}

int
Img4DecodeGetPropertyData(const DERItem *a1, DERTag tag, DERByte **a4, DERSize *a5)
{
    int rv;
    DERItem var_50;
    DERMonster var_40[2];

    var_50.data = a1->data;
    var_50.length = a1->length;

    rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
    if (rv) {
        return rv;
    }

    if (var_40[1].tag != ASN1_OCTET_STRING) {
        return DR_UnexpectedTag;
    }

    *a4 = var_40[1].item.data;
    *a5 = var_40[1].item.length;
    return 0;
}

int
Img4DecodeEvaluateCertificateProperties(TheImg4 *img4)
{
    int rv;
    DERItem var_130;
    DERItem var_118;
    DERMonster var_108[2];
    DERMonster var_D8[2];
    DERDecodedInfo var_A8;
    DERDecodedInfo var_90;
    DERTag tag;
    DERSequence var_70;
    DERSequence var_60;

    if (img4 == NULL) {
        return DR_ParamErr;
    }
    rv = DERDecodeSeqInit(&img4->manifest.img4_blob, &tag, &var_60);
    if (rv) {
        return rv;
    }

    if (tag != ASN1_CONSTR_SET) {
        return DR_UnexpectedTag;
    }

    while (!DERDecodeSeqNext(&var_60, &var_90)) {
        if (var_90.tag != (E000000000000000 | 'OBJP')) {
            if (var_90.tag != (E000000000000000 | 'MANP')) {
                return DR_UnexpectedTag;
            }
            var_130 = img4->manp;
        } else {
            var_130 = img4->objp;
        }

        rv = DERImg4DecodeProperty(&var_90.content, var_90.tag, var_D8);
        if (rv) {
            return rv;
        }

        if (var_D8[1].tag != ASN1_CONSTR_SET) {
            return DR_UnexpectedTag;
        }

        rv = DERDecodeSeqContentInit(&var_D8[1].item, &var_70);
        if (rv) {
            return rv;
        }

        while (!DERDecodeSeqNext(&var_70, &var_A8)) {
            rv = DERImg4DecodeProperty(&var_A8.content, var_A8.tag, var_108);
            if (rv) {
                return rv;
            }

            rv = DERImg4DecodeContentFindItemWithTag(&var_130, var_A8.tag, &var_118);
            if ((var_108[1].tag & (ASN1_CLASS_MASK | ASN1_METHOD_MASK)) > ASN1_CONTEXT_SPECIFIC) {
                if (var_108[1].tag != (ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC)) {
                    if (var_108[1].tag != (ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 1)) {
                        return DR_UnexpectedTag;
                    }
                    if (rv == DR_EndOfSequence) {
                        rv = 0;
                    }
                }
                if (rv) {
                    return rv;
                }
            } else {
                if (var_108[1].tag != ASN1_OCTET_STRING && var_108[1].tag != ASN1_INTEGER && var_108[1].tag != ASN1_BOOLEAN) {
                    return DR_UnexpectedTag;
                }
                if (rv) {
                    return rv;
                }
                if (!IS_EQUAL(var_A8.content, var_118)) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

int
Img4DecodeEvaluateDictionaryProperties(const DERItem *a1, DictType what, int (*property_cb)(DERTag, DERItem *, DictType, void *), void *ctx)
{
    int rv;
    DERMonster var_98[2];
    DERItem var_68;
    DERSequence var_58;
    DERDecodedInfo var_48;

    if (!property_cb) {
        return DR_ParamErr;
    }

    rv = DERDecodeSeqContentInit(a1, &var_58);
    if (rv) {
        return rv;
    }

    while (1) {
        rv = DERDecodeSeqNext(&var_58, &var_48);
        if (rv == DR_EndOfSequence) {
            return 0;
        }
        if (rv) {
            return rv;
        }
        rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
        if (rv) {
            return rv;
        }

        if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
            return DR_UnexpectedTag;
        }

        if ((var_48.tag & E000000000000000) == 0) {
            return DR_UnexpectedTag;
        }

        var_68.data = var_48.content.data;
        var_68.length = var_48.content.length;
        rv = property_cb(var_48.tag, &var_68, what, ctx);
        if (rv) {
            return rv;
        }
    }
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

int
Img4DecodeEvaluateTrust(int type, TheImg4 *img4, int (*property_cb)(DERTag, DERItem *, DictType, void *), void *ctx)
{
    int rv;
    DERDecodedInfo var_88;
    DERMonster var_70[2];

    if (img4 == NULL || property_cb == NULL) {
        return DR_ParamErr;
    }
    if (img4->manifestRaw.data == NULL) {
        return DR_ParamErr;
    }

    sha1_digest(img4->manifest.theset.data, img4->manifest.theset.length, img4->manifest.theset_digest);

    rv = img4_verify_signature_with_chain(
        img4->manifest.chain_blob.data, img4->manifest.chain_blob.length,
        img4->manifest.sig_blob.data, img4->manifest.sig_blob.length,
        img4->manifest.theset_digest, 20, &img4->manifest.img4_blob.data, &img4->manifest.img4_blob.length);
    if (rv) {
        return rv;
    }

    if (!img4->manifest.img4_blob.length) {
        return DR_DecodeError;
    }

    rv = DERDecodeItem(&img4->manifest.theset, &var_88);
    if (rv) {
        return rv;
    }

    if (var_88.tag != ASN1_CONSTR_SET) {
        return -1;
    }

    rv = DERImg4DecodeFindProperty(&var_88.content, E000000000000000 | 'MANB', ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }

    img4->manb = var_70[1].item;

    rv = DERImg4DecodeFindProperty(&img4->manb, E000000000000000 | 'MANP', ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }

    img4->manp = var_70[1].item;

    rv = DERImg4DecodeFindProperty(&img4->manb, E000000000000000 | (unsigned int)type, ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }
    img4->objp = var_70[1].item;

    rv = Img4DecodeEvaluateCertificateProperties(img4);
    if (rv) {
        return rv;
    }

    sha1_digest(img4->payloadRaw.data, img4->payloadRaw.length, img4->payload.full_digest);
    img4->payloadHashed = 1;

    rv = Img4DecodeEvaluateDictionaryProperties(&img4->manp, DictMANP, property_cb, ctx);
    if (rv) {
        return rv;
    }

    rv = Img4DecodeEvaluateDictionaryProperties(&img4->objp, DictOBJP, property_cb, ctx);
    if (rv) {
        return rv;
    }

    sha1_digest(img4->manifestRaw.data, img4->manifestRaw.length, img4->manifest.full_digest);
    img4->manifestHashed = 1;

    return 0;
}

int
checkBoolean(DERTag tag, const DERItem *der, bool value)
{
    int rv;
    bool var_11 = false;

    rv = Img4DecodeGetPropertyBoolean(der, tag, &var_11);
    if (rv) {
        return rv;
    }
    return (var_11 != value) ? -1 : 0;
}

int
checkInteger64(int less_than, DERTag tag, const DERItem *der, uint64_t value)
{
    int rv;
    uint64_t var_18 = 0;

    rv = Img4DecodeGetPropertyInteger64(der, tag, &var_18);
    if (rv) {
        return rv;
    }
    if (less_than == 1) {
        return (var_18 < value) ? -1 : 0;
    }
    if (less_than == 0) {
        return (var_18 != value) ? -1 : 0;
    }
    return 0;
}

int
checkData(DERTag tag, const DERItem *der, void *data)
{
    int rv;
    DERSize var_1C;
    DERByte *var_18;

    rv = Img4DecodeGetPropertyData(der, tag, &var_18, &var_1C);
    if (rv) {
        return rv;
    }
    return memcmp(var_18, data, var_1C) ? -1 : 0;
}

int
image4_validate_property_callback(DERTag tag, DERItem *b, DictType what, void *ctx)
{
    int rv;
    TheImg4 *img4 = ((CTX *)ctx)->img4;
    ContextU *ctxu = ((CTX *)ctx)->unknown;
    ContextH *ctxh = ((CTX *)ctx)->hardware;

    DERByte *var_58;
    DERSize var_50;
    uint64_t var_48;
    unsigned char var_3C[20];

    switch (what) {
        case DictMANP:
            switch ((unsigned int)tag) {
                case 'AMNM':
                    rv = checkBoolean('AMNM', b, true);
                    if (rv == -1) {
                        return 0;
                    }
                    if (rv) {
                        return rv;
                    }
                    ctxu->field_3 = 1;
                    return 0;
                case 'BNCH':
                    if (!ctxh->field_2C) {
                        return 0;
                    }
                    if (!ctxh->field_2A) {
                        var_48 = ctxh->field_30;
                    } else {
                        rv = Img4DecodeGetRestoreInfoData(img4, 'BNCN', &var_58, &var_50);
                        if (rv) {
                            return rv;
                        }
                        if (var_50 != 8) {
                            return 0;
                        }
                        memmove(&var_48, var_58, 8);
                    }
                    doHash(&var_48, 8, var_3C);
                    return checkData('BNCH', b, var_3C);
                case 'BORD':
                    return checkInteger64(0, 'BORD', b, ctxh->BORD);
                case 'CEPO':
                    return checkInteger64(1, 'CEPO', b, ctxh->SEPO);
                case 'CHIP':
                    return checkInteger64(0, 'CHIP', b, ctxh->CHIP);
                case 'CPRO':
                    return checkBoolean('CPRO', b, ctxh->CPRO);
                case 'CSEC':
                    return checkBoolean('CSEC', b, ctxh->CSEC);
                case 'ECID':
                    return checkInteger64(0, 'ECID', b, ctxh->ECID);
                case 'SDOM':
                    return checkInteger64(0, 'SDOM', b, ctxh->SDOM);
            }
            return 0;
        case DictOBJP:
            switch ((unsigned int)tag) {
                case 'DGST':
                    rv = Img4DecodeCopyPayloadHash(img4, ctxu->payload_hash, 20);
                    if (rv) {
                        return rv;
                    }
                    return checkData('DGST', b, ctxu->payload_hash);
                case 'DPRO':
                    rv = checkBoolean('DPRO', b, true);
                    if (rv == -1) {
                        return 0;
                    }
                    if (rv) {
                        return rv;
                    }
                    ctxu->field_0 = 1;
                    return 0;
                case 'EKEY':
                    rv = checkBoolean('EKEY', b, true);
                    if (rv == -1) {
                        return 0;
                    }
                    if (rv) {
                        return rv;
                    }
                    ctxu->field_2 = 1;
                    return 0;
                case 'EPRO':
                    ctxu->field_5 = 1;
                    rv = checkBoolean('EPRO', b, true);
                    if (rv == -1) {
                        return 0;
                    }
                    if (rv) {
                        return rv;
                    }
                    ctxu->field_4 = 1;
                    return 0;
                case 'ESEC':
                    ctxu->field_7 = 1;
                    rv = checkBoolean('ESEC', b, true);
                    if (rv == -1) {
                        return 0;
                    }
                    if (rv) {
                        return rv;
                    }
                    ctxu->field_6 = 1;
                    return 0;
            }
            return 0;
    }
    return 0;
}

static int
objp_property_callback(DERTag tag, DERItem *b, DictType what, void *ctx)
{
    int rv;
    if (what == DictOBJP && (unsigned int)tag == 'DGST') {
        const DERMonster *tmp = (DERMonster *)ctx;
        const DERItem *payloadRaw = &tmp->item;
        unsigned char digest[64];

        DERSize var_1C;
        DERByte *var_18;
        rv = Img4DecodeGetPropertyData(b, tag, &var_18, &var_1C);
        if (rv) {
            return rv;
        }

        if (var_1C == 20) {
            sha1_digest(payloadRaw->data, payloadRaw->length, digest);
        } else {
#ifdef USE_CORECRYPTO
            ccdigest(&ccsha384_ltc_di, payloadRaw->length, payloadRaw->data, digest);
#elif defined(USE_COMMONCRYPTO)
            CC_SHA384(payloadRaw->data, payloadRaw->length, digest);
#else
            SHA384(payloadRaw->data, payloadRaw->length, digest);
#endif
        }
        if (tmp->tag) {
            memmove(var_18, digest, var_1C);
            return 0;
        }
        return !!memcmp(digest, var_18, var_1C);
    }
    return 0;
}

static int
find_hash(const TheImg4 *img4, unsigned int type, int update)
{
    int rv;
    DERDecodedInfo var_88;
    DERMonster var_70[2];
    DERItem manb, manp, objp;
    DERMonster tmp;

    if (img4->manifestRaw.data == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeItem(&img4->manifest.theset, &var_88);
    if (rv) {
        return rv;
    }
    if (var_88.tag != ASN1_CONSTR_SET) {
        return -1;
    }

    rv = DERImg4DecodeFindProperty(&var_88.content, E000000000000000 | 'MANB', ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }
    manb = var_70[1].item;

    rv = DERImg4DecodeFindProperty(&manb, E000000000000000 | 'MANP', ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }
    manp = var_70[1].item;

    rv = DERImg4DecodeFindProperty(&manb, E000000000000000 | type, ASN1_CONSTR_SET, var_70);
    if (rv) {
        return rv;
    }
    objp = var_70[1].item;

    tmp.item = img4->payloadRaw;
    tmp.tag = update; // XXX abuse
    return Img4DecodeEvaluateDictionaryProperties(&objp, DictOBJP, objp_property_callback, (void *)&tmp);
}

#include <errno.h>
#include <fcntl.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccaes.h>
#elif !defined(USE_COMMONCRYPTO)
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
    uint64_t usize;
    unsigned type;
    int hasnonce;
    int wasimg4;
    int uphash;
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
makeKeybag(DERItem *where, const DERByte *a, const DERByte *b)
{
    const DERItemSpec wrap[2] = {
        { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_ENC_WRITE_DER },
        { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_ENC_WRITE_DER }
    };

    int rv;
    DERItem elements[3];
    DERItem first, second;
    unsigned char one = 1, two = 2;

    elements[0].data = &one;
    elements[0].length = sizeof(one);
    elements[1].data = (DERByte *)a;
    elements[1].length = 16;
    elements[2].data = (DERByte *)a + 16;
    elements[2].length = 32;
    rv = aDEREncodeSequence(&first, ASN1_CONSTR_SEQUENCE, elements, 3, kbagSpecs, -1);
    if (rv) {
        return rv;
    }

    elements[0].data = &two;
    elements[0].length = sizeof(two);
    elements[1].data = (DERByte *)b;
    elements[1].length = 16;
    elements[2].data = (DERByte *)b + 16;
    elements[2].length = 32;
    rv = aDEREncodeSequence(&second, ASN1_CONSTR_SEQUENCE, elements, 3, kbagSpecs, -1);
    if (rv) {
        free(first.data);
        return rv;
    }

    elements[0].data = first.data;
    elements[0].length = first.length;
    elements[1].data = second.data;
    elements[1].length = second.length;
    rv = aDEREncodeSequence(where, ASN1_CONSTR_SEQUENCE, elements, 2, wrap, -1);
    free(first.data);
    free(second.data);

    return rv;
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
        uint64_t usize = fd->usize;
        pfd->ioctl(pfd, IOCTL_LZFSE_GET_LENGTH, &usize);
        rv = makeCompression(&compr, fd->lzfse, usize);
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
parseargs(ContextH *ctxh, const char *s)
{
    do {
        size_t index = strcspn(s, " \t,\r\n");
        if (index) {
            const char *p = memchr(s, '=', index);
            if (p && p - s == 4) {
                size_t vallen = s + index - ++p;
                switch (GET_DWORD_BE(s, 0)) {
#define CASE(fourcc, field) case fourcc: ctxh->field = getint(p, vallen, ctxh->field); printf(#field " = 0x%llx\n", (unsigned long long)ctxh->field); break
                    CASE('BORD', BORD);
                    CASE('CHIP', CHIP);
                    CASE('ECID', ECID);
                    CASE('CPRO', CPRO);
                    CASE('CSEC', CSEC);
                    CASE('SDOM', SDOM);
                    CASE('SEPO', SEPO);
#undef CASE
                }
            }
        }
        s += index;
        s += strspn(s, " \t,\r\n");
    } while (*s);
}

static int
validate(TheImg4 *img4, unsigned type, const char *args)
{
    int rv;
    CTX ctx;

    ctx.img4 = img4;
    ctx.hardware = malloc(sizeof(ContextH));
    assert(ctx.hardware);
    memset(ctx.hardware, 0, sizeof(ContextH));

    ctx.hardware->BORD = 0x12;
    ctx.hardware->CHIP = 0x8960;
    ctx.hardware->ECID = 0;
    ctx.hardware->CPRO = 1;
    ctx.hardware->CSEC = 1;
    ctx.hardware->SDOM = 1;
    ctx.hardware->SEPO = 1;
    parseargs(ctx.hardware, args);

    ctx.hardware->field_2A = 1; /* use Img4DecodeGetRestoreInfoData() */
    ctx.hardware->field_2C = 1;
    if (img4->restoreInfo.nonce.data == NULL) {
        ctx.hardware->field_2A = 0; /* use field_30 */
        if (!ctx.hardware->field_30) {
            ctx.hardware->field_2C = 0; /* field_30 was not set, skip */
        }
    }

    ctx.unknown = malloc(sizeof(ContextU));
    assert(ctx.unknown);
    memset(ctx.unknown, 0, sizeof(ContextU));
    rv = Img4DecodeManifestExists(img4, &ctx.unknown->has_manifest);
    if (rv == 0) {
        rv = Img4DecodeEvaluateTrust(type, img4, image4_validate_property_callback, &ctx);
    }
    free(ctx.unknown);
    free(ctx.hardware);
    return rv;
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
#if !defined(USE_CORECRYPTO) && !defined(USE_COMMONCRYPTO)
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

    if (fd->uphash && fd->manifest.data) {
        TheImg4 *img4 = parse(out.data, out.length);
        if (!img4) {
            free(out.data);
            return -1;
        }
        rv = find_hash(img4, fd->type, 1);
        free(img4);
        if (rv) {
            free(out.data);
            return -1;
        }
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
        case IOCTL_IMG4_SET_KEYBAG2: {
            DERItem item;
            const DERByte *a = va_arg(ap, DERByte *);
            const DERByte *b = va_arg(ap, DERByte *);
            if (!b) {
                b = a;
            }
            rv = makeKeybag(&item, a, b);
            if (rv == 0) {
                free(ctx->keybag.data);
                ctx->keybag = item;
            }
            break;
        }
        case IOCTL_IMG4_SET_KEYBAG: {
            unsigned i;
            DERTag tag;
            DERSequence seq;
            DERDecodedInfo info;
            DERItem kbag;
            kbag.data = va_arg(ap, void *);
            kbag.length = va_arg(ap, size_t);
            if (DERDecodeSeqInit(&kbag, &tag, &seq)) {
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
            }
            if (i == 2) {
                DERItem knew;
                rv = derdup(&knew, &kbag);
                if (rv == 0) {
                    free(ctx->keybag.data);
                    ctx->keybag = knew;
                }
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
        case IOCTL_LZFSE_SET_NOCOMP:
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
img4_reopen(FHANDLE other, const unsigned char *ivkey, int flags)
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
    uint64_t usize = 0;
    DERByte *der;
    DERSize derlen;

    if (!other) {
        return NULL;
    }
    if (other->flags == O_WRONLY) {
        goto closeit;
    }
    if (other->flags == O_RDONLY && (flags & FLAG_IMG4_UPDATE_HASH)) {
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

    if (flags == O_RDONLY) {
        DERDecodedInfo seq;
        item.data = buf;
        item.length = total;
        rv = DERDecodeItem(&item, &seq);
        if (rv == 0 && seq.tag == ASN1_CONSTR_SEQUENCE) {
            if (item.data + item.length > seq.content.data + seq.content.length) {
                fprintf(stderr, "[w] extra %zu bytes discarded\n", item.data + item.length - (seq.content.data + seq.content.length));
                total = seq.content.data + seq.content.length - item.data;
            }
        }
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

    if (flags & FLAG_IMG4_VERIFY_HASH) {
        rv = find_hash(img4, type, 0);
        if (rv) {
            printf("[e] image fast check failed: %d\n", rv);
            goto freeimg;
        }
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
    if (flags & FLAG_IMG4_SKIP_DECOMPRESSION) {
        goto okay;
    }
#ifdef iOS10
    if (img4->payload.compression.data && img4->payload.compression.length) {
        DERItem tmp[2];
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

  okay:
    ops = calloc(1, sizeof(struct file_ops_img4));
    if (!ops) {
        goto closefd;
    }
    ctx = ops;
    ctx->pfd = pfd;
    ctx->type = type;
    ctx->lzfse = deco;
    ctx->usize = usize;
    ctx->other = other;
    ctx->wasimg4 = (img4->payloadRaw.data != NULL);
    ctx->uphash = (flags & FLAG_IMG4_UPDATE_HASH);

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
