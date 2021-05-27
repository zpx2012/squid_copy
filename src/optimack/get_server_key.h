#include "ssl_local.h"
#include <openssl/kdf.h>
#include <openssl/modes.h>
#include "evp.h"
#include "modes_local.h"
#include "include/openssl/aes.h"
#include "include/openssl/engine.h"

static int tls1_PRF(SSL *s,
                    const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen, int fatal)
{
    const EVP_MD *md = ssl_prf_md(s);
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (md == NULL) {
        /* Should never happen */
        if (fatal)
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS1_PRF,
                     ERR_R_INTERNAL_ERROR);
        else
            SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0
        || EVP_PKEY_derive(pctx, out, &olen) <= 0) {
        if (fatal)
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS1_PRF,
                     ERR_R_INTERNAL_ERROR);
        else
            SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int tls1_generate_key_block(SSL *s, unsigned char *km, size_t num)
{
    int ret;

    /* Calls SSLfatal() as required */
    ret = tls1_PRF(s,
                   TLS_MD_KEY_EXPANSION_CONST,
                   TLS_MD_KEY_EXPANSION_CONST_SIZE, s->s3->server_random,
                   SSL3_RANDOM_SIZE, s->s3->client_random, SSL3_RANDOM_SIZE,
                   NULL, 0, NULL, 0, s->session->master_key,
                   s->session->master_key_length, km, num, 1);
    printf("ret: %d\n", ret);
    printf("s->s3->client_random: \n");
    for (int i = 0; i < 10; i++)
        printf("\\x%02X", s->s3->client_random[i]);
    printf("\n");
    printf("TLS_MD_KEY_EXPANSION_CONST: %s\n", TLS_MD_KEY_EXPANSION_CONST);
    return ret;
}

static void get_server_write_key(SSL *s, unsigned char *buffer) {
    unsigned char *key_block_buffer;

    key_block_buffer = (unsigned char*) malloc(56);
    memset(key_block_buffer, 0, 56);
    tls1_generate_key_block(s, key_block_buffer, 56);
    printf("key_block_buffer: \n");
    for (int i = 0; i < 56; i++)
        printf("\\x%02X", key_block_buffer[i]);
    printf("\n");
    memcpy(buffer, key_block_buffer + 16, 16);
    
    free(key_block_buffer);
    return;
}

static void get_server_write_iv_salt(SSL *s, unsigned char *buffer) {
    unsigned char *key_block_buffer;

    key_block_buffer = (unsigned char*) malloc(56);
    tls1_generate_key_block(s, key_block_buffer, 56);
    memcpy(buffer, key_block_buffer + 36, 4);
    
    free(key_block_buffer);
    return;
}

int test_include() {
    printf("Hello from openssl-bio-fetch!!!\n");
    return 1;
}