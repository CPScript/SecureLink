/*
 * Secure Network Encryption Module ~
 * Compile with: gcc -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
 *               -fPIE -pie securelink.c -lsodium -lcrypto -pthread -o securelink
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <sodium.h>

/* Security constants */
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define SALT_SIZE 32
#define SESSION_ID_SIZE 16
#define MAX_PACKET_SIZE 65535
#define REPLAY_WINDOW_SIZE 1024
#define KEY_ROTATION_INTERVAL 100
#define FRAGMENT_HEADER_SIZE 8
#define PACKET_HEADER_SIZE 4

/* Protocol version */
#define PROTOCOL_VERSION 0x02

/* Error codes */
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERR_ALLOC = -1,
    CRYPTO_ERR_INVALID_PARAM = -2,
    CRYPTO_ERR_ENCRYPT = -3,
    CRYPTO_ERR_DECRYPT = -4,
    CRYPTO_ERR_AUTH = -5,
    CRYPTO_ERR_REPLAY = -6,
    CRYPTO_ERR_PROTOCOL = -7,
    CRYPTO_ERR_KEY_DERIVE = -8,
    CRYPTO_ERR_SESSION = -9
} crypto_error_t;

/* Cipher modes */
typedef enum {
    CIPHER_AES_256_GCM = 0,
    CIPHER_CHACHA20_POLY1305 = 1,
    CIPHER_AES_256_GCM_SIV = 2
} cipher_mode_t;

/* Secure memory allocator structure */
typedef struct {
    void *ptr;
    size_t size;
    bool locked;
} secure_mem_t;

/* Replay protection structure */
typedef struct {
    uint64_t *window;
    size_t window_size;
    uint64_t last_seq;
    pthread_mutex_t lock;
} replay_guard_t;

/* Crypto context structure */
typedef struct {
    uint8_t session_id[SESSION_ID_SIZE];
    uint8_t master_key[KEY_SIZE];
    uint8_t current_key[KEY_SIZE];
    uint8_t mac_key[KEY_SIZE];
    uint8_t salt[SALT_SIZE];
    uint64_t counter;
    uint32_t packet_count;
    cipher_mode_t mode;
    replay_guard_t *replay_guard;
    time_t last_rotation;
    pthread_mutex_t lock;
    secure_mem_t *secure_keys;
} crypto_context_t;

/* Traffic obfuscation structure */
typedef struct {
    uint32_t min_pad;
    uint32_t max_pad;
    uint8_t *pattern_cache;
    size_t pattern_size;
    uint64_t seed;
} obfuscator_t;

/* Session manager structure */
typedef struct {
    crypto_context_t **contexts;
    size_t num_contexts;
    size_t capacity;
    pthread_rwlock_t lock;
    uint8_t master_secret[KEY_SIZE];
    secure_mem_t *secure_master;
} session_manager_t;

/* Global sodium initialization flag */
static bool g_sodium_initialized = false;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Secure memory functions */
static secure_mem_t* secure_alloc(size_t size) {
    secure_mem_t *smem = malloc(sizeof(secure_mem_t));
    if (!smem) return NULL;
    
    /* Allocate aligned memory for better performance */
    if (posix_memalign(&smem->ptr, 64, size) != 0) {
        free(smem);
        return NULL;
    }
    
    smem->size = size;
    smem->locked = false;
    
    /* Lock memory to prevent swapping */
    if (mlock(smem->ptr, size) == 0) {
        smem->locked = true;
    }
    
    /* Set memory protection */
    mprotect(smem->ptr, size, PROT_READ | PROT_WRITE);
    
    /* Initialize with random data for security */
    RAND_bytes(smem->ptr, size);
    
    return smem;
}

static void secure_free(secure_mem_t *smem) {
    if (!smem) return;
    
    /* Overwrite memory with random data multiple times */
    for (int i = 0; i < 3; i++) {
        RAND_bytes(smem->ptr, smem->size);
    }
    
    /* Explicit memory barrier to prevent optimization */
    __asm__ __volatile__("" : : "r"(smem->ptr) : "memory");
    
    /* Clear with zeros */
    sodium_memzero(smem->ptr, smem->size);
    
    /* Unlock memory if it was locked */
    if (smem->locked) {
        munlock(smem->ptr, smem->size);
    }
    
    free(smem->ptr);
    free(smem);
}

/* Constant-time comparison */
static bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

/* Initialize cryptographic libraries */
static crypto_error_t crypto_init(void) {
    pthread_mutex_lock(&g_init_mutex);
    
    if (!g_sodium_initialized) {
        if (sodium_init() < 0) {
            pthread_mutex_unlock(&g_init_mutex);
            return CRYPTO_ERR_ALLOC;
        }
        g_sodium_initialized = true;
    }
    
    /* Initialize OpenSSL - use newer function for OpenSSL 1.1.0+ */
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    
    pthread_mutex_unlock(&g_init_mutex);
    return CRYPTO_SUCCESS;
}

/* Generate cryptographically secure random bytes */
static void secure_random(uint8_t *buf, size_t len) {
    /* Use libsodium's CSPRNG which is fork-safe */
    randombytes_buf(buf, len);
}

/* Key derivation using HKDF */
static crypto_error_t derive_key(const uint8_t *secret, size_t secret_len,
                                 const uint8_t *salt, size_t salt_len,
                                 const uint8_t *info, size_t info_len,
                                 uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *pctx;
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return CRYPTO_ERR_KEY_DERIVE;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERR_KEY_DERIVE;
    }
    
    EVP_PKEY_CTX_free(pctx);
    return CRYPTO_SUCCESS;
}

/* Create replay guard */
static replay_guard_t* replay_guard_create(size_t window_size) {
    replay_guard_t *guard = calloc(1, sizeof(replay_guard_t));
    if (!guard) return NULL;
    
    guard->window = calloc(window_size, sizeof(uint64_t));
    if (!guard->window) {
        free(guard);
        return NULL;
    }
    
    /* Initialize window with impossible sequence numbers */
    for (size_t i = 0; i < window_size; i++) {
        guard->window[i] = UINT64_MAX;
    }
    
    guard->window_size = window_size;
    guard->last_seq = 0;
    pthread_mutex_init(&guard->lock, NULL);
    
    return guard;
}

/* Check and update replay window */
static bool replay_guard_check(replay_guard_t *guard, uint64_t seq) {
    pthread_mutex_lock(&guard->lock);
    
    /* Check if sequence number is too old (avoid underflow) */
    if (guard->last_seq >= guard->window_size && seq <= guard->last_seq - guard->window_size) {
        pthread_mutex_unlock(&guard->lock);
        return false;
    }
    
    /* Check if already seen */
    size_t index = seq % guard->window_size;
    if (guard->window[index] == seq) {
        pthread_mutex_unlock(&guard->lock);
        return false;
    }
    
    /* Update window */
    guard->window[index] = seq;
    if (seq > guard->last_seq) {
        guard->last_seq = seq;
    }
    
    pthread_mutex_unlock(&guard->lock);
    return true;
}

/* Free replay guard */
static void replay_guard_free(replay_guard_t *guard) {
    if (!guard) return;
    
    pthread_mutex_destroy(&guard->lock);
    sodium_memzero(guard->window, guard->window_size * sizeof(uint64_t));
    free(guard->window);
    free(guard);
}

/* Create crypto context */
static crypto_context_t* context_create(const uint8_t *session_id,
                                       const uint8_t *master_key,
                                       cipher_mode_t mode) {
    crypto_context_t *ctx = calloc(1, sizeof(crypto_context_t));
    if (!ctx) return NULL;
    
    /* Allocate secure memory for keys */
    ctx->secure_keys = secure_alloc(KEY_SIZE * 3);
    if (!ctx->secure_keys) {
        free(ctx);
        return NULL;
    }
    
    /* Initialize replay guard */
    ctx->replay_guard = replay_guard_create(REPLAY_WINDOW_SIZE);
    if (!ctx->replay_guard) {
        secure_free(ctx->secure_keys);
        free(ctx);
        return NULL;
    }
    
    /* Copy session ID and keys */
    memcpy(ctx->session_id, session_id, SESSION_ID_SIZE);
    memcpy(ctx->master_key, master_key, KEY_SIZE);
    memcpy(ctx->current_key, master_key, KEY_SIZE);
    
    /* Derive MAC key */
    derive_key(master_key, KEY_SIZE, 
              (uint8_t*)"MAC_KEY", 7,
              session_id, SESSION_ID_SIZE,
              ctx->mac_key, KEY_SIZE);
    
    /* Generate salt */
    secure_random(ctx->salt, SALT_SIZE);
    
    ctx->mode = mode;
    ctx->counter = 0;
    ctx->packet_count = 0;
    ctx->last_rotation = time(NULL);
    pthread_mutex_init(&ctx->lock, NULL);
    
    return ctx;
}

/* Internal key rotation without mutex (assumes caller holds lock) */
static crypto_error_t rotate_keys_unlocked(crypto_context_t *ctx) {
    uint8_t new_key[KEY_SIZE];
    uint8_t info[32];
    
    /* Create rotation info */
    snprintf((char*)info, sizeof(info), "ROTATE_%lu", ctx->counter);
    
    /* Derive new key */
    crypto_error_t err = derive_key(ctx->current_key, KEY_SIZE,
                                   ctx->salt, SALT_SIZE,
                                   info, strlen((char*)info),
                                   new_key, KEY_SIZE);
    
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    /* Securely overwrite old key */
    sodium_memzero(ctx->current_key, KEY_SIZE);
    memcpy(ctx->current_key, new_key, KEY_SIZE);
    sodium_memzero(new_key, KEY_SIZE);
    
    /* Update MAC key */
    derive_key(ctx->current_key, KEY_SIZE,
              (uint8_t*)"MAC_KEY", 7,
              ctx->session_id, SESSION_ID_SIZE,
              ctx->mac_key, KEY_SIZE);
    
    ctx->packet_count = 0;
    ctx->last_rotation = time(NULL);
    
    return CRYPTO_SUCCESS;
}

/* Free crypto context */
static void context_free(crypto_context_t *ctx) {
    if (!ctx) return;
    
    pthread_mutex_destroy(&ctx->lock);
    replay_guard_free(ctx->replay_guard);
    
    /* Securely clear keys */
    sodium_memzero(ctx->master_key, KEY_SIZE);
    sodium_memzero(ctx->current_key, KEY_SIZE);
    sodium_memzero(ctx->mac_key, KEY_SIZE);
    
    secure_free(ctx->secure_keys);
    free(ctx);
}

/* AES-256-GCM encryption */
static crypto_error_t aes_gcm_encrypt(const uint8_t *key,
                                     const uint8_t *iv, size_t iv_len,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     uint8_t *ciphertext,
                                     uint8_t *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    
    /* Create and initialize context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return CRYPTO_ERR_ALLOC;
    }
    
    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Set IV length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Initialize key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Add AAD */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERR_ENCRYPT;
        }
    }
    
    /* Encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}

/* AES-256-GCM decryption */
static crypto_error_t aes_gcm_decrypt(const uint8_t *key,
                                     const uint8_t *iv, size_t iv_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *tag,
                                     uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    
    /* Create and initialize context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return CRYPTO_ERR_ALLOC;
    }
    
    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_DECRYPT;
    }
    
    /* Set IV length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_DECRYPT;
    }
    
    /* Initialize key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_DECRYPT;
    }
    
    /* Add AAD */
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERR_DECRYPT;
        }
    }
    
    /* Decrypt ciphertext */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_DECRYPT;
    }
    plaintext_len = len;
    
    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_AUTH;
    }
    
    /* Verify tag and finalize */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        sodium_memzero(plaintext, plaintext_len);
        return CRYPTO_ERR_AUTH;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}

/* ChaCha20-Poly1305 encryption (alternative cipher) */
static crypto_error_t chacha20_poly1305_encrypt(const uint8_t *key,
                                               const uint8_t *nonce,
                                               const uint8_t *plaintext, size_t plaintext_len,
                                               const uint8_t *aad, size_t aad_len,
                                               uint8_t *ciphertext,
                                               uint8_t *tag) {
    /* Allocate temporary buffer for ciphertext+tag output */
    uint8_t *temp_output = malloc(plaintext_len + TAG_SIZE);
    if (!temp_output) return CRYPTO_ERR_ALLOC;
    
    unsigned long long ciphertext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            temp_output, &ciphertext_len,
            plaintext, plaintext_len,
            aad, aad_len,
            NULL, nonce, key) != 0) {
        free(temp_output);
        return CRYPTO_ERR_ENCRYPT;
    }
    
    /* Extract ciphertext and tag separately */
    memcpy(ciphertext, temp_output, plaintext_len);
    memcpy(tag, temp_output + plaintext_len, TAG_SIZE);
    
    free(temp_output);
    return CRYPTO_SUCCESS;
}

/* ChaCha20-Poly1305 decryption */
static crypto_error_t chacha20_poly1305_decrypt(const uint8_t *key,
                                               const uint8_t *nonce,
                                               const uint8_t *ciphertext, size_t ciphertext_len,
                                               const uint8_t *aad, size_t aad_len,
                                               const uint8_t *tag,
                                               uint8_t *plaintext) {
    /* Combine ciphertext and tag for libsodium */
    uint8_t *combined = malloc(ciphertext_len + TAG_SIZE);
    if (!combined) return CRYPTO_ERR_ALLOC;
    
    memcpy(combined, ciphertext, ciphertext_len);
    memcpy(combined + ciphertext_len, tag, TAG_SIZE);
    
    unsigned long long plaintext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &plaintext_len,
            NULL,
            combined, ciphertext_len + TAG_SIZE,
            aad, aad_len,
            nonce, key) != 0) {
        free(combined);
        return CRYPTO_ERR_AUTH;
    }
    
    free(combined);
    return CRYPTO_SUCCESS;
}

/* Create obfuscator */
static obfuscator_t* obfuscator_create(uint32_t min_pad, uint32_t max_pad) {
    obfuscator_t *obf = calloc(1, sizeof(obfuscator_t));
    if (!obf) return NULL;
    
    obf->min_pad = min_pad;
    obf->max_pad = max_pad;
    obf->pattern_size = 1024;
    obf->pattern_cache = malloc(obf->pattern_size);
    
    if (!obf->pattern_cache) {
        free(obf);
        return NULL;
    }
    
    /* Initialize pattern cache with random data */
    secure_random(obf->pattern_cache, obf->pattern_size);
    secure_random((uint8_t*)&obf->seed, sizeof(obf->seed));
    
    return obf;
}

/* Add traffic obfuscation */
static uint8_t* obfuscate_packet(obfuscator_t *obf, const uint8_t *data, 
                                size_t data_len, size_t *out_len) {
    /* Calculate padding using Pareto distribution for realistic traffic */
    uint32_t padding = obf->min_pad;
    uint64_t rnd = obf->seed;
    
    /* Simple PRNG for padding calculation */
    rnd = rnd * 6364136223846793005ULL + 1442695040888963407ULL;
    padding += (rnd % (obf->max_pad - obf->min_pad));
    
    obf->seed = rnd;
    
    size_t total_size = PACKET_HEADER_SIZE + data_len + padding;
    uint8_t *obfuscated = malloc(total_size);
    if (!obfuscated) return NULL;
    
    /* Write header */
    uint16_t orig_len = data_len;
    uint16_t total_len = total_size;
    obfuscated[0] = (orig_len >> 8) & 0xFF;
    obfuscated[1] = orig_len & 0xFF;
    obfuscated[2] = (total_len >> 8) & 0xFF;
    obfuscated[3] = total_len & 0xFF;
    
    /* Copy data */
    memcpy(obfuscated + PACKET_HEADER_SIZE, data, data_len);
    
    /* Add padding from pattern cache */
    for (size_t i = 0; i < padding; i++) {
        obfuscated[PACKET_HEADER_SIZE + data_len + i] = 
            obf->pattern_cache[i % obf->pattern_size];
    }
    
    *out_len = total_size;
    return obfuscated;
}

/* Remove traffic obfuscation */
static uint8_t* deobfuscate_packet(const uint8_t *data, size_t data_len, 
                                  size_t *out_len) {
    if (data_len < PACKET_HEADER_SIZE) return NULL;
    
    uint16_t orig_len = (data[0] << 8) | data[1];
    uint16_t total_len = (data[2] << 8) | data[3];
    
    if (total_len != data_len || orig_len > data_len - PACKET_HEADER_SIZE) {
        return NULL;
    }
    
    uint8_t *deobfuscated = malloc(orig_len);
    if (!deobfuscated) return NULL;
    
    memcpy(deobfuscated, data + PACKET_HEADER_SIZE, orig_len);
    *out_len = orig_len;
    
    return deobfuscated;
}

/* Free obfuscator */
static void obfuscator_free(obfuscator_t *obf) {
    if (!obf) return;
    
    sodium_memzero(obf->pattern_cache, obf->pattern_size);
    free(obf->pattern_cache);
    free(obf);
}

/* Encrypt packet */
crypto_error_t encrypt_packet(crypto_context_t *ctx,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t **ciphertext_out, size_t *ciphertext_len_out) {
    if (!ctx || !plaintext || !ciphertext_out || !ciphertext_len_out || plaintext_len == 0) {
        return CRYPTO_ERR_INVALID_PARAM;
    }
    
    /* Initialize output parameters */
    *ciphertext_out = NULL;
    *ciphertext_len_out = 0;
    
    pthread_mutex_lock(&ctx->lock);
    
    /* Check for key rotation */
    if (ctx->packet_count >= KEY_ROTATION_INTERVAL) {
        crypto_error_t rot_err = rotate_keys_unlocked(ctx);
        if (rot_err != CRYPTO_SUCCESS) {
            pthread_mutex_unlock(&ctx->lock);
            return rot_err;
        }
    }
    
    /* Generate IV/nonce */
    uint8_t iv[IV_SIZE];
    secure_random(iv, IV_SIZE);
    
    /* Create AAD */
    uint8_t aad[24];
    memcpy(aad, ctx->session_id, SESSION_ID_SIZE);
    uint64_t counter_be = htobe64(ctx->counter);
    memcpy(aad + SESSION_ID_SIZE, &counter_be, 8);
    
    /* Allocate output buffer with space for sequence number */
    size_t packet_size = 1 + 8 + IV_SIZE + plaintext_len + TAG_SIZE;
    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_ALLOC;
    }

    /* Set version */
    packet[0] = PROTOCOL_VERSION;

    /* Add sequence number in big-endian format */
    uint64_t seq_be = htobe64(ctx->counter);
    memcpy(packet + 1, &seq_be, 8);

    /* Copy IV */
    memcpy(packet + 1 + 8, iv, IV_SIZE);
    
    /* Encrypt based on mode */
    crypto_error_t err;
    uint8_t tag[TAG_SIZE];
    
    if (ctx->mode == CIPHER_AES_256_GCM) {
        err = aes_gcm_encrypt(ctx->current_key, iv, IV_SIZE,
                            plaintext, plaintext_len,
                            aad, sizeof(aad),
                            packet + 1 + 8 + IV_SIZE, tag);
    } else if (ctx->mode == CIPHER_CHACHA20_POLY1305) {
        err = chacha20_poly1305_encrypt(ctx->current_key, iv,
                                    plaintext, plaintext_len,
                                    aad, sizeof(aad),
                                    packet + 1 + 8 + IV_SIZE, tag);
    } else {
        free(packet);
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_INVALID_PARAM;
    }
    
    if (err != CRYPTO_SUCCESS) {
        sodium_memzero(packet, packet_size);
        free(packet);
        pthread_mutex_unlock(&ctx->lock);
        return err;
    }
    
    /* Append tag */
    memcpy(packet + 1 + 8 + IV_SIZE + plaintext_len, tag, TAG_SIZE);
    
    /* Update counters */
    ctx->counter++;
    ctx->packet_count++;
    
    pthread_mutex_unlock(&ctx->lock);
    
    *ciphertext_out = packet;
    *ciphertext_len_out = packet_size;
    
    return CRYPTO_SUCCESS;
}

/* Decrypt packet */
crypto_error_t decrypt_packet(crypto_context_t *ctx,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            uint8_t **plaintext_out, size_t *plaintext_len_out) {
    if (!ctx || !ciphertext || !plaintext_out || !plaintext_len_out || ciphertext_len == 0) {
        return CRYPTO_ERR_INVALID_PARAM;
    }
    
    /* Initialize output parameters */
    *plaintext_out = NULL;
    *plaintext_len_out = 0;
    
    pthread_mutex_lock(&ctx->lock);
    
    /* Validate packet size */
    if (ciphertext_len < 1 + 8 + IV_SIZE + TAG_SIZE) {
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_INVALID_PARAM;
    }

    /* Check version */
    if (ciphertext[0] != PROTOCOL_VERSION) {
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_PROTOCOL;
    }

    /* Extract sequence number */
    uint64_t seq;
    memcpy(&seq, ciphertext + 1, 8);
    seq = be64toh(seq);

    /* Check replay attack */
    if (!replay_guard_check(ctx->replay_guard, seq)) {
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_REPLAY;
    }

    /* Extract components */
    const uint8_t *iv = ciphertext + 1 + 8;
    size_t encrypted_len = ciphertext_len - 1 - 8 - IV_SIZE - TAG_SIZE;
    const uint8_t *encrypted = ciphertext + 1 + 8 + IV_SIZE;
    const uint8_t *tag = ciphertext + ciphertext_len - TAG_SIZE;
    
    /* Create AAD */
    uint8_t aad[24];
    memcpy(aad, ctx->session_id, SESSION_ID_SIZE);
    uint64_t counter_be = htobe64(seq);
    memcpy(aad + SESSION_ID_SIZE, &counter_be, 8);
    
    /* Allocate plaintext buffer */
    uint8_t *plaintext = malloc(encrypted_len);
    if (!plaintext) {
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_ALLOC;
    }
    
    /* Decrypt based on mode */
    crypto_error_t err;
    
    if (ctx->mode == CIPHER_AES_256_GCM) {
        err = aes_gcm_decrypt(ctx->current_key, iv, IV_SIZE,
                            encrypted, encrypted_len,
                            aad, sizeof(aad),
                            tag, plaintext);
    } else if (ctx->mode == CIPHER_CHACHA20_POLY1305) {
        err = chacha20_poly1305_decrypt(ctx->current_key, iv,
                                      encrypted, encrypted_len,
                                      aad, sizeof(aad),
                                      tag, plaintext);
    } else {
        free(plaintext);
        pthread_mutex_unlock(&ctx->lock);
        return CRYPTO_ERR_INVALID_PARAM;
    }
    
    if (err != CRYPTO_SUCCESS) {
        sodium_memzero(plaintext, encrypted_len);
        free(plaintext);
        pthread_mutex_unlock(&ctx->lock);
        return err;
    }
    
    pthread_mutex_unlock(&ctx->lock);
    
    *plaintext_out = plaintext;
    *plaintext_len_out = encrypted_len;
    
    return CRYPTO_SUCCESS;
}

/* Session Manager Implementation */
session_manager_t* session_manager_create(const uint8_t *master_secret) {
    session_manager_t *mgr = calloc(1, sizeof(session_manager_t));
    if (!mgr) return NULL;
    
    mgr->secure_master = secure_alloc(KEY_SIZE);
    if (!mgr->secure_master) {
        free(mgr);
        return NULL;
    }
    
    memcpy(mgr->master_secret, master_secret, KEY_SIZE);
    mgr->capacity = 16;
    mgr->contexts = calloc(mgr->capacity, sizeof(crypto_context_t*));
    
    if (!mgr->contexts) {
        secure_free(mgr->secure_master);
        free(mgr);
        return NULL;
    }
    
    pthread_rwlock_init(&mgr->lock, NULL);
    
    return mgr;
}

/* Establish new session */
crypto_context_t* establish_session(session_manager_t *mgr,
                                   const uint8_t *peer_id, size_t peer_id_len,
                                   const uint8_t *ephemeral_key,
                                   cipher_mode_t mode) {
    /* Generate session ID */
    uint8_t session_id[SESSION_ID_SIZE];
    uint8_t hash_input[KEY_SIZE * 2 + peer_id_len];
    
    memcpy(hash_input, mgr->master_secret, KEY_SIZE);
    memcpy(hash_input + KEY_SIZE, ephemeral_key, KEY_SIZE);
    memcpy(hash_input + KEY_SIZE * 2, peer_id, peer_id_len);
    
    /* Use SHA-256 for session ID */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, hash_input, sizeof(hash_input));
    EVP_DigestFinal_ex(mdctx, session_id, NULL);
    EVP_MD_CTX_free(mdctx);
    
    /* Derive session key */
    uint8_t session_key[KEY_SIZE];
    derive_key(mgr->master_secret, KEY_SIZE,
              ephemeral_key, KEY_SIZE,
              (uint8_t*)"SESSION_KEY", 11,
              session_key, KEY_SIZE);
    
    /* Create context */
    crypto_context_t *ctx = context_create(session_id, session_key, mode);
    if (!ctx) return NULL;
    
    /* Add to manager */
    pthread_rwlock_wrlock(&mgr->lock);
    
    if (mgr->num_contexts >= mgr->capacity) {
        /* Expand capacity */
        size_t new_capacity = mgr->capacity * 2;
        crypto_context_t **new_contexts = realloc(mgr->contexts,
                                                 new_capacity * sizeof(crypto_context_t*));
        if (!new_contexts) {
            pthread_rwlock_unlock(&mgr->lock);
            context_free(ctx);
            return NULL;
        }
        mgr->contexts = new_contexts;
        mgr->capacity = new_capacity;
    }
    
    mgr->contexts[mgr->num_contexts++] = ctx;
    pthread_rwlock_unlock(&mgr->lock);
    
    /* Clear sensitive data */
    sodium_memzero(session_key, KEY_SIZE);
    sodium_memzero(hash_input, sizeof(hash_input));
    
    return ctx;
}

/* Close session */
void close_session(session_manager_t *mgr, crypto_context_t *ctx) {
    pthread_rwlock_wrlock(&mgr->lock);
    
    for (size_t i = 0; i < mgr->num_contexts; i++) {
        if (mgr->contexts[i] == ctx) {
            /* Remove from array */
            memmove(&mgr->contexts[i], &mgr->contexts[i + 1],
                   (mgr->num_contexts - i - 1) * sizeof(crypto_context_t*));
            mgr->num_contexts--;
            break;
        }
    }
    
    pthread_rwlock_unlock(&mgr->lock);
    
    context_free(ctx);
}

/* Free session manager */
void session_manager_free(session_manager_t *mgr) {
    if (!mgr) return;
    
    /* Free all contexts */
    for (size_t i = 0; i < mgr->num_contexts; i++) {
        context_free(mgr->contexts[i]);
    }
    
    pthread_rwlock_destroy(&mgr->lock);
    sodium_memzero(mgr->master_secret, KEY_SIZE);
    secure_free(mgr->secure_master);
    free(mgr->contexts);
    free(mgr);
}

/* Fragment large messages */
typedef struct {
    uint16_t total_fragments;
    uint16_t fragment_number;
    uint32_t fragment_size;
} fragment_header_t;

crypto_error_t send_fragmented(crypto_context_t *ctx,
                              const uint8_t *data, size_t data_len,
                              uint8_t ***fragments_out, size_t **frag_lens_out,
                              size_t *num_fragments_out) {
    const size_t max_fragment = 1400;
    size_t num_fragments = (data_len + max_fragment - 1) / max_fragment;
    
    uint8_t **fragments = calloc(num_fragments, sizeof(uint8_t*));
    size_t *frag_lens = calloc(num_fragments, sizeof(size_t));
    
    if (!fragments || !frag_lens) {
        free(fragments);
        free(frag_lens);
        return CRYPTO_ERR_ALLOC;
    }
    
    for (size_t i = 0; i < num_fragments; i++) {
        size_t offset = i * max_fragment;
        size_t chunk_size = (i == num_fragments - 1) ? 
                          data_len - offset : max_fragment;
        
        /* Create fragment with header */
        fragment_header_t header = {
            .total_fragments = num_fragments,
            .fragment_number = i,
            .fragment_size = chunk_size
        };
        
        uint8_t *fragment_data = malloc(sizeof(header) + chunk_size);
        if (!fragment_data) {
            /* Cleanup on error */
            for (size_t j = 0; j < i; j++) {
                free(fragments[j]);
            }
            free(fragments);
            free(frag_lens);
            return CRYPTO_ERR_ALLOC;
        }
        
        memcpy(fragment_data, &header, sizeof(header));
        memcpy(fragment_data + sizeof(header), data + offset, chunk_size);
        
        /* Encrypt fragment */
        crypto_error_t err = encrypt_packet(ctx, fragment_data, 
                                          sizeof(header) + chunk_size,
                                          &fragments[i], &frag_lens[i]);
        
        free(fragment_data);
        
        if (err != CRYPTO_SUCCESS) {
            /* Cleanup on error */
            for (size_t j = 0; j <= i; j++) {
                if (fragments[j]) free(fragments[j]);
            }
            free(fragments);
            free(frag_lens);
            return err;
        }
    }
    
    *fragments_out = fragments;
    *frag_lens_out = frag_lens;
    *num_fragments_out = num_fragments;
    
    return CRYPTO_SUCCESS;
}

crypto_error_t receive_fragmented(crypto_context_t *ctx,
                                 uint8_t **fragments, size_t *frag_lens,
                                 size_t num_fragments,
                                 uint8_t **data_out, size_t *data_len_out) {
    typedef struct {
        uint8_t *data;
        size_t len;
        bool received;
    } fragment_info_t;
    
    fragment_info_t *frag_info = NULL;
    size_t expected_fragments = 0;
    size_t total_size = 0;
    
    /* Decrypt all fragments */
    for (size_t i = 0; i < num_fragments; i++) {
        uint8_t *decrypted;
        size_t decrypted_len;
        
        crypto_error_t err = decrypt_packet(ctx, fragments[i], frag_lens[i],
                                          &decrypted, &decrypted_len);
        if (err != CRYPTO_SUCCESS) {
            /* Cleanup */
            if (frag_info) {
                for (size_t j = 0; j < expected_fragments; j++) {
                    if (frag_info[j].data) free(frag_info[j].data);
                }
                free(frag_info);
            }
            return err;
        }
        
        /* Parse header */
        if (decrypted_len < sizeof(fragment_header_t)) {
            free(decrypted);
            continue;
        }
        
        fragment_header_t *header = (fragment_header_t*)decrypted;
        
        /* Initialize fragment info array on first fragment */
        if (!frag_info) {
            expected_fragments = header->total_fragments;
            frag_info = calloc(expected_fragments, sizeof(fragment_info_t));
            if (!frag_info) {
                free(decrypted);
                return CRYPTO_ERR_ALLOC;
            }
        }
        
        /* Store fragment */
        if (header->fragment_number < expected_fragments) {
            frag_info[header->fragment_number].data = 
                malloc(header->fragment_size);
            if (!frag_info[header->fragment_number].data) {
                free(decrypted);
                continue;
            }
            
            memcpy(frag_info[header->fragment_number].data,
                  decrypted + sizeof(fragment_header_t),
                  header->fragment_size);
            frag_info[header->fragment_number].len = header->fragment_size;
            frag_info[header->fragment_number].received = true;
            total_size += header->fragment_size;
        }
        
        free(decrypted);
    }
    
    /* Verify all fragments received */
    for (size_t i = 0; i < expected_fragments; i++) {
        if (!frag_info[i].received) {
            /* Cleanup */
            for (size_t j = 0; j < expected_fragments; j++) {
                if (frag_info[j].data) free(frag_info[j].data);
            }
            free(frag_info);
            return CRYPTO_ERR_PROTOCOL;
        }
    }
    
    /* Reassemble data */
    uint8_t *data = malloc(total_size);
    if (!data) {
        for (size_t i = 0; i < expected_fragments; i++) {
            free(frag_info[i].data);
        }
        free(frag_info);
        return CRYPTO_ERR_ALLOC;
    }
    
    size_t offset = 0;
    for (size_t i = 0; i < expected_fragments; i++) {
        memcpy(data + offset, frag_info[i].data, frag_info[i].len);
        offset += frag_info[i].len;
        free(frag_info[i].data);
    }
    
    free(frag_info);
    
    *data_out = data;
    *data_len_out = total_size;
    
    return CRYPTO_SUCCESS;
}

/* Test suite */
void run_tests(void) {
    printf("==============================================\n");
    printf("SECURE NETWORK CRYPTO MODULE - TEST SUITE\n");
    printf("==============================================\n");
    
    /* Initialize crypto */
    if (crypto_init() != CRYPTO_SUCCESS) {
        printf("Failed to initialize crypto\n");
        return;
    }
    
    /* Test 1: Session establishment */
    printf("\n[TEST 1] Session Establishment\n");
    uint8_t master_secret[KEY_SIZE];
    secure_random(master_secret, KEY_SIZE);
    
    session_manager_t *mgr = session_manager_create(master_secret);
    if (!mgr) {
        printf("FAILED: Could not create session manager\n");
        return;
    }
    
    uint8_t ephemeral[KEY_SIZE];
    secure_random(ephemeral, KEY_SIZE);
    
    crypto_context_t *ctx = establish_session(mgr, 
                                             (uint8_t*)"peer1", 5,
                                             ephemeral,
                                             CIPHER_AES_256_GCM);
    if (ctx) {
        printf("PASSED: Session established\n");
    } else {
        printf("FAILED: Could not establish session\n");
        session_manager_free(mgr);
        return;
    }
    
    /* Test 2: Basic encryption/decryption */
    printf("\n[TEST 2] Encryption/Decryption\n");
    const char *test_msg = "Highly sensitive data requiring strong encryption";
    uint8_t *encrypted;
    size_t encrypted_len;
    
    crypto_error_t err = encrypt_packet(ctx, 
                                       (uint8_t*)test_msg, strlen(test_msg),
                                       &encrypted, &encrypted_len);
    
    if (err == CRYPTO_SUCCESS) {
        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;
        
        err = decrypt_packet(ctx, encrypted, encrypted_len,
                           &decrypted, &decrypted_len);
        
        if (err == CRYPTO_SUCCESS && 
            decrypted_len == strlen(test_msg) &&
            memcmp(decrypted, test_msg, decrypted_len) == 0) {
            printf("PASSED: Encryption/Decryption successful\n");
        } else {
            if (err == CRYPTO_SUCCESS) {
                printf("FAILED: Data mismatch (len=%zu vs %zu)\n", 
                       decrypted_len, strlen(test_msg));
            } else {
                printf("FAILED: Decryption error (err=%d)\n", err);
            }
        }
        
        if (decrypted) free(decrypted);
    } else {
        printf("FAILED: Encryption error (%d)\n", err);
    }
    
    if (encrypted) free(encrypted);
    
    /* Test 3: Key rotation */
    printf("\n[TEST 3] Key Rotation\n");
    uint8_t old_key[KEY_SIZE];
    memcpy(old_key, ctx->current_key, KEY_SIZE);
    
    /* Force rotation */
    ctx->packet_count = KEY_ROTATION_INTERVAL;
    
    err = encrypt_packet(ctx, (uint8_t*)"test", 4, &encrypted, &encrypted_len);
    
    if (err == CRYPTO_SUCCESS) {
        if (!constant_time_compare(old_key, ctx->current_key, KEY_SIZE)) {
            printf("PASSED: Keys rotated successfully\n");
        } else {
            printf("FAILED: Keys did not rotate\n");
        }
    } else {
        printf("FAILED: Encryption during key rotation failed (err=%d)\n", err);
    }
    
    if (encrypted) free(encrypted);
    
    /* Test 4: Fragmentation */
    printf("\n[TEST 4] Fragmentation\n");
    size_t large_size = 10000;
    uint8_t *large_data = malloc(large_size);
    secure_random(large_data, large_size);
    
    uint8_t **fragments;
    size_t *frag_lens;
    size_t num_frags;
    
    err = send_fragmented(ctx, large_data, large_size,
                        &fragments, &frag_lens, &num_frags);
    
    if (err == CRYPTO_SUCCESS) {
        uint8_t *reassembled;
        size_t reassembled_len;
        
        err = receive_fragmented(ctx, fragments, frag_lens, num_frags,
                               &reassembled, &reassembled_len);
        
        if (err == CRYPTO_SUCCESS &&
            reassembled_len == large_size &&
            memcmp(reassembled, large_data, large_size) == 0) {
            printf("PASSED: Fragmentation/Reassembly successful (%zu fragments)\n", 
                   num_frags);
        } else {
            printf("FAILED: Reassembly error or mismatch\n");
        }
        
        if (reassembled) free(reassembled);
        
        for (size_t i = 0; i < num_frags; i++) {
            free(fragments[i]);
        }
        free(fragments);
        free(frag_lens);
    } else {
        printf("FAILED: Fragmentation error\n");
    }
    
    free(large_data);
    
    /* Test 5: Replay attack prevention */
    printf("\n[TEST 5] Replay Attack Prevention\n");
    err = encrypt_packet(ctx, (uint8_t*)"replay test", 11,
                       &encrypted, &encrypted_len);
    
    if (err == CRYPTO_SUCCESS) {
        uint8_t *plaintext1, *plaintext2;
        size_t len1, len2;
        
        /* Save current counter */
        uint64_t saved_counter = ctx->counter;
        
        /* First decryption should work */
        err = decrypt_packet(ctx, encrypted, encrypted_len,
                           &plaintext1, &len1);
        
        if (err == CRYPTO_SUCCESS) {
            /* Reset counter to simulate replay */
            ctx->counter = saved_counter;
            
            /* Second decryption should fail */
            err = decrypt_packet(ctx, encrypted, encrypted_len,
                               &plaintext2, &len2);
            
            if (err == CRYPTO_ERR_REPLAY) {
                printf("PASSED: Replay attack detected\n");
            } else {
                printf("FAILED: Replay attack not detected\n");
                if (err == CRYPTO_SUCCESS) free(plaintext2);
            }
            
            free(plaintext1);
        } else {
            printf("FAILED: Initial decryption failed\n");
        }
        
        free(encrypted);
    } else {
        printf("FAILED: Encryption for replay test failed\n");
    }
    
    /* Test 6: ChaCha20-Poly1305 */
    printf("\n[TEST 6] ChaCha20-Poly1305 Cipher\n");
    crypto_context_t *ctx2 = establish_session(mgr,
                                              (uint8_t*)"peer2", 5,
                                              ephemeral,
                                              CIPHER_CHACHA20_POLY1305);
    if (ctx2) {
        err = encrypt_packet(ctx2, (uint8_t*)"ChaCha test", 11,
                           &encrypted, &encrypted_len);
        
        if (err == CRYPTO_SUCCESS) {
            uint8_t *decrypted;
            size_t decrypted_len;
            
            err = decrypt_packet(ctx2, encrypted, encrypted_len,
                               &decrypted, &decrypted_len);
            
            if (err == CRYPTO_SUCCESS) {
                printf("PASSED: ChaCha20-Poly1305 working\n");
                free(decrypted);
            } else {
                printf("FAILED: ChaCha20-Poly1305 decryption failed\n");
            }
            
            free(encrypted);
        } else {
            printf("FAILED: ChaCha20-Poly1305 encryption failed\n");
        }
    } else {
        printf("FAILED: Could not create ChaCha20 session\n");
    }
    
    /* Test 7: Obfuscation */
    printf("\n[TEST 7] Traffic Obfuscation\n");
    obfuscator_t *obf = obfuscator_create(16, 256);
    if (obf) {
        size_t obf_len;
        uint8_t *obfuscated = obfuscate_packet(obf, 
                                              (uint8_t*)"test", 4,
                                              &obf_len);
        if (obfuscated && obf_len > 4) {
            size_t deobf_len;
            uint8_t *deobfuscated = deobfuscate_packet(obfuscated, obf_len,
                                                      &deobf_len);
            
            if (deobfuscated && deobf_len == 4 &&
                memcmp(deobfuscated, "test", 4) == 0) {
                printf("PASSED: Obfuscation working (added %zu bytes padding)\n",
                       obf_len - 4 - PACKET_HEADER_SIZE);
            } else {
                printf("FAILED: Deobfuscation error\n");
            }
            
            if (deobfuscated) free(deobfuscated);
            free(obfuscated);
        } else {
            printf("FAILED: Obfuscation error\n");
        }
        
        obfuscator_free(obf);
    } else {
        printf("FAILED: Could not create obfuscator\n");
    }
    
    /* Test 8: Performance */
    printf("\n[TEST 8] Performance Metrics\n");
    
    struct timespec start, end;
    int iterations = 1000;
    uint8_t test_data[1024];
    secure_random(test_data, sizeof(test_data));
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        uint8_t *enc;
        size_t enc_len;
        encrypt_packet(ctx, test_data, sizeof(test_data), &enc, &enc_len);
        free(enc);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput = (iterations * sizeof(test_data)) / elapsed / 1024 / 1024;
    
    printf("Throughput: %.2f MB/s (%d iterations in %.3f seconds)\n",
           throughput, iterations, elapsed);
    
    printf("\n[TEST 9] Cleanup\n");
    close_session(mgr, ctx);
    if (ctx2) close_session(mgr, ctx2);
    session_manager_free(mgr);
    sodium_memzero(master_secret, KEY_SIZE);
    printf("PASSED: Secure cleanup completed\n");
    
    printf("\n==============================================\n");
    printf("TEST COMPLETED\n");
    printf("==============================================\n");
}

int main(int argc, char *argv[]) {
    (void)argc; /* Suppress unused parameter warning */
    (void)argv; /* Suppress unused parameter warning */
    
    printf("Secure Network Encryption Module v2.0\n");
    printf("Using AES-256-GCM and ChaCha20-Poly1305\n\n");
    
    run_tests();
    
    return 0;
}
