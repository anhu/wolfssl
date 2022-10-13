/* maxq10xx.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _WOLFPORT_MAXQ10XX_H_
#define _WOLFPORT_MAXQ10XX_H_

#if defined(WOLFSSL_MAXQ1061) || defined(WOLFSSL_MAXQ1065) || \
    defined(WOLFSSL_MAXQ108x)

#include <wolfssl/wolfcrypt/types.h>

#ifndef WC_DH_TYPE_DEFINED
    typedef struct DhKey DhKey;
    #define WC_DH_TYPE_DEFINED
#endif

#ifndef WC_RNG_TYPE_DEFINED /* guard on redeclaration */
    typedef struct OS_Seed OS_Seed;
    typedef struct WC_RNG WC_RNG;
    #ifdef WC_RNG_SEED_CB
        typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
    #endif
    #define WC_RNG_TYPE_DEFINED
#endif

#ifdef WOLF_CRYPTO_CB
    #ifdef WOLFSSL_MAXQ1061
    #endif /* WOLFSSL_MAXQ1061 */

    #ifdef WOLFSSL_MAXQ1065
        #define MAXQ_AESGCM
        #define MAXQ_SHA256
        #define MAXQ_RNG
        #define MAXQ_ECC
    #endif /* WOLFSSL_MAXQ1065 */

    #ifdef WOLFSSL_MAXQ108x
        #define MAXQ_AESGCM
        #define MAXQ_SHA256
        #define MAXQ_RNG
        #define MAXQ_ECC
        #define ENABLE_RSA
    #endif /* WOLFSSL_MAXQ108x */
#endif /* WOLF_CRYPTO_CB */

#ifdef HAVE_PK_CALLBACKS
struct WOLFSSL_CTX;
typedef struct WOLFSSL WOLFSSL;
#endif /* HAVE_PK_CALLBACKS */

#ifdef WOLFSSL_MAXQ10XX_TLS
typedef struct WOLFSSL WOLFSSL;
typedef struct DecodedCert DecodedCert;
typedef struct ecc_key ecc_key;
typedef struct DerBuffer DerBuffer;

typedef struct {
    int use_hw_keys;
    DerBuffer* device_cert;
} maxq_ssl_t;
#endif /* WOLFSSL_MAXQ10XX_TLS */

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    typedef struct Aes Aes;
    typedef struct wc_Sha256 wc_Sha256;
    typedef struct ecc_key ecc_key;

    typedef struct {
        int key_obj_id;
        int key_pending;
        unsigned char key[32];
    } maxq_aes_t;

    typedef struct {
        int hash_running;
        int soft_hash;
    } maxq_sha256_t;

    typedef struct {
        int key_obj_id;
        int key_pending;
        int hw_ecc;
        int hw_storage;
        unsigned char ecc_key[32 * 3];
    } maxq_ecc_t;
#endif /* WOLFSSL_MAXQ10XX_CRYPTO */

#ifdef WOLF_CRYPTO_CB
    typedef struct wc_CryptoInfo wc_CryptoInfo;
#endif

int maxq10xx_port_init(void);

#ifdef HAVE_PK_CALLBACKS
void maxq10xx_SetupPkCallbacks(struct WOLFSSL_CTX* ctx, int isTLS13);
void maxq10xx_SetTls13Side(int side);

int maxq10xx_perform_tls13_record_processing(WOLFSSL* ssl, int is_encrypt,
                                             byte* out, const byte* in,
                                             word32 sz, const byte* iv,
                                             word32 ivSz, byte* authTag,
                                             word32 authTagSz,
                                             const byte* authIn,
                                             word32 authInSz);

void maxq10xx_SetRsaPssSignature(byte* in, word32 inSz);
int maxq10xx_RsaPssVerify(WOLFSSL* ssl, byte* hashed_msg, word32 hashed_msg_sz,
                          byte* signature, word32 sig_sz);

#ifdef HAVE_HKDF
int maxq10xx_HkdfExpandLabel(byte* okm, word32 okmLen,
                             const byte* prk, word32 prkLen,
                             const byte* protocol, word32 protocolLen,
                             const byte* label, word32 labelLen,
                             const byte* info, word32 infoLen,
                             int digest);

#endif /* HAVE_HKDF */
#endif /* HAVE_PK_CALLBACKS */

#ifdef WOLFSSL_MAXQ10XX_TLS
int maxq10xx_process_server_certificate(WOLFSSL* ssl, DecodedCert* p_cert);
int maxq10xx_process_server_key_exchange(WOLFSSL* ssl, byte p_sig_algo,
                                         const byte* p_sig, word32 p_sig_len,
                                         const byte* p_rand, word32 p_rand_len,
                                         const byte* p_server_params,
                                         word32 p_server_params_len);

int maxq10xx_perform_client_key_exchange(WOLFSSL* ssl, ecc_key* p_key, ecc_key*
                                         p_peer_key);
int maxq10xx_make_tls_master_secret(WOLFSSL* ssl, const byte* p_client_rand,
                                    const byte* p_server_rand, int is_psk);
int maxq10xx_perform_client_finished(WOLFSSL* ssl, const byte* p_label,
                                     word32 p_label_len, const byte* p_seed,
                                     word32 p_seed_len, byte* p_dest,
                                     word32 p_dest_len);
int maxq10xx_perform_tls_record_processing(WOLFSSL* ssl, int is_encrypt,
                                           byte* out, const byte* in, word32 sz,
                                           const byte* iv, word32 ivSz,
                                           byte* authTag, word32 authTagSz,
                                           const byte* authIn, word32 authInSz);
int maxq10xx_sign_device_cert(WOLFSSL* ssl, const byte* p_in, word32 p_in_len,
                              byte* p_out, word32* p_out_len);

#endif /* WOLFSSL_MAXQ10XX_TLS */

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
int wc_MAXQ10XX_AesSetKey(Aes* aes, const byte* userKey, word32 keylen);
void wc_MAXQ10XX_AesFree(Aes* aes);

void wc_MAXQ10XX_Sha256Copy(wc_Sha256* sha256);
void wc_MAXQ10XX_Sha256Free(wc_Sha256* sha256);

int wc_MAXQ10XX_EccSetKey(ecc_key* key, word32 keysize);
void wc_MAXQ10XX_EccFree(ecc_key* key);
#endif /* WOLFSSL_MAXQ10XX_CRYPTO */

#ifdef WOLF_CRYPTO_CB
    int wolfSSL_MAXQ10XX_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx);
#endif

#endif /* WOLFSSL_MAXQ1061 || WOLFSSL_MAXQ1065 || WOLFSSL_MAXQ108x */
#endif /* _WOLFPORT_MAXQ10XX_H_ */
