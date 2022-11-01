/* maxq10xx-wolfssl-client.c
 *
 * Based on client-tls-pkcallback.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows how to write a simple TLS client that uses the features
 * features of the Analog Devices MAXQ 1065 and 1080. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if (defined(WOLFSSL_MAXQ1065) || defined(WOLFSSL_MAXQ108x)) && \
    defined(HAVE_PK_CALLBACKS) && defined(WOLF_CRYPTO_CB) && \
    !defined(NO_PSK) && !defined(HAVE_EXTENDED_MASTER) && \
    defined(NO_WOLFSSL_SERVER)

/* -------------- */
/* Configurations */
/* -------------- */

/* Please define this if you want wolfSSL's debug output */
#define WANT_DEBUG

/* Please set the server's address and the port it listens on */
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT   11111

/* Please define one of USE_ECDHE_ECDSA, USE_FFDHE_RSA, USE_PSK */
//#define USE_ECDHE_ECDSA
//#define USE_FFDHE_RSA
#define USE_PSK

/* Please define one of USE_TLSV13, USE_TLSV12 */
//#define USE_TLSV13
#define USE_TLSV12

/* Please set the location of the dummy private keys */
#if defined(USE_ECDHE_ECDSA) || defined(USE_PSK)
#define KEYPUB_FILE "/home/anthony/ecc-p256-pub.pem"
#else
#define KEYPUB_FILE "/home/anthony/rsa-2048-pub.pem"
#endif

/* ------------------------------------ */
/* No modifications required below here */
/* ------------------------------------ */

#ifdef USE_PSK

/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, kIdentityStr, id_max_len);

    if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {
        /* test key in hex is 0x1a2b3c4d , in decimal 439,041,101 , we're using
           unsigned binary */
        key[0] = 0x1a;
        key[1] = 0x2b;
        key[2] = 0x3c;
        key[3] = 0x4d;

        return 4;   /* length of key in octets or 0 for error */
    }
    else {
        int i;
        int b = 0x01;

        for (i = 0; i < 32; i++, b += 0x22) {
            if (b >= 0x100)
                b = 0x01;
            key[i] = b;
        }

        return 32;   /* length of key in octets or 0 for error */
    }
}

#ifdef USE_TLSV13

static WC_INLINE unsigned int my_psk_client_cs_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len, const char* ciphersuite)
{
    int i;
    int b = 0x01;

    (void)ssl;
    (void)hint;
    (void)key_max_len;

#ifdef WOLFSSL_PSK_MULTI_ID_PER_CS
    /* Multiple calls for each cipher suite. First identity byte indicates the
     * number of identites seen so far for cipher suite. */
    if (identity[0] != 0) {
        return 0;
    }
#endif

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, kIdentityStr, id_max_len);
    XSTRNCAT(identity, ciphersuite + XSTRLEN(ciphersuite) - 6, id_max_len);

    for (i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100)
            b = 0x01;
        key[i] = b;
    }

    return 32;   /* length of key in octets or 0 for error */
}

#endif /* USE_TLSV13 */
#endif /* USE_PSK */

int main(int argc, char** argv)
{
    int                ret, err;
    int                sockfd = SOCKET_INVALID;
    struct sockaddr_in servAddr;
    char               buff[256];
    size_t             len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    /* Create a socket that uses an internet IPv4 address.
     * Sets the socket to be stream based (TCP).
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto exit;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, DEFAULT_SERVER, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto exit;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto exit;
    }

    /*---------------------------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------------------------*/
#ifdef WANT_DEBUG
    wolfSSL_Debugging_ON();
#endif

    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto exit;
    }

    /* Create and initialize WOLFSSL_CTX */
#ifdef USE_TLSV13
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif

    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto exit;
    }

    /* Load the dummy private key; actually a public key. The actual private
     * key resides in MAXQ 10xx. */
    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEYPUB_FILE,
                                    WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEYPUB_FILE);
        goto exit;
    }

#ifdef USE_PSK
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
#ifdef USE_TLSV13
    wolfSSL_CTX_set_psk_client_cs_callback(ctx, my_psk_client_cs_cb);
    wolfSSL_CTX_set_psk_callback_ctx(ctx, (void*)"TLS13-AES128-GCM-SHA256");
#else
    wolfSSL_CTX_set_psk_callback_ctx(ctx, (void*)"PSK-AES128-CCM-8");
#endif /* USE_TLSV13 */
#endif /* USE_PSK */

    /* validate peer certificate */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto exit;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto exit;
    }

    /* Connect to wolfSSL on the server side */
    do {
        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WC_PENDING_E);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto exit;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL) {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        ret = -1;
        goto exit;
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto exit;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto exit;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    ret = 0; /* success */

exit:
    /* Cleanup and return */
    if (sockfd != SOCKET_INVALID)
        close(sockfd);
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);

    wolfSSL_Cleanup();

    return ret;
}

#else

int main(int argc, char** argv)
{
    printf("Warning: Required flags have not been used!\n"
           "Please configure with the following flags:\n"
           "    --enable-pkcallbacks\n"
           "    --enable-cryptocb\n"
           "    --disable-extended-master\n"
           "    --enable-psk\n"
           "    --enable-aesccm\n"
           "    --enable-tls13\n"
           "    --with-maxq10xx=MAXQ108x|MAXQ1065\n"
           "    CFLAGS=-DNO_WOLFSSL_SERVER\n"
);
    return -1;
}
#endif /* (WOLFSSL_MAXQ1065 || WOLFSSL_MAXQ108x) && HAVE_PK_CALLBACKS &&
        * WOLF_CRYPTO_CB && !NO_PSK && !HAVE_EXTENDED_MASTER &&
        * NO_WOLFSSL_SERVER */
