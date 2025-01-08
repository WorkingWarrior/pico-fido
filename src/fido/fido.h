#ifndef _FIDO_H_
#define _FIDO_H_

// ===== Platform-specific includes =====
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#endif

#ifndef ESP_PLATFORM
#include "common.h"
#else
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#include "mbedtls/ecdsa.h"

#ifndef ENABLE_EMULATION
#include "hid/ctap_hid.h"
#else
#include <stdbool.h>
#endif

// ===== Constants =====
// Key and Path
#define CTAP_PUBKEY_LEN          (65)
#define KEY_PATH_LEN             (32)
#define KEY_PATH_ENTRIES         (KEY_PATH_LEN / sizeof(uint32_t))
#define SHA256_DIGEST_LENGTH     (32)
#define KEY_HANDLE_LEN           (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)

#define FIDO_KEY_PURPOSE         10022
#define HARDENED_BIT             0x80000000
#define KEY_ENTRIES_START        1

// FIDO2 Algorithms
#define FIDO2_ALG_ES256         -7
#define FIDO2_ALG_EDDSA         -8
#define FIDO2_ALG_ES384         -35
#define FIDO2_ALG_ES512         -36
#define FIDO2_ALG_ECDH_ES_HKDF_256  -25
#define FIDO2_ALG_ES256K        -47
#define FIDO2_ALG_RS256         -257
#define FIDO2_ALG_RS384         -258
#define FIDO2_ALG_RS512         -259

// FIDO2 Curves
#define FIDO2_CURVE_P256        1
#define FIDO2_CURVE_P384        2
#define FIDO2_CURVE_P521        3
#define FIDO2_CURVE_X25519      4
#define FIDO2_CURVE_X448        5
#define FIDO2_CURVE_ED25519     6
#define FIDO2_CURVE_ED448       7
#define FIDO2_CURVE_P256K1      8

// Authentication Flags
#define FIDO2_AUT_FLAG_UP       0x1
#define FIDO2_AUT_FLAG_UV       0x4
#define FIDO2_AUT_FLAG_AT       0x40
#define FIDO2_AUT_FLAG_ED       0x80

// Options & Limits
#define FIDO2_OPT_EA           0x01
#define MAX_PIN_RETRIES        8
#define MAX_CREDENTIAL_COUNT_IN_LIST  16
#define MAX_CRED_ID_LENGTH     1024
#define MAX_RESIDENT_CREDENTIALS  256
#define MAX_CREDBLOB_LENGTH    128
#define MAX_MSG_SIZE           1024
#define MAX_FRAGMENT_LENGTH    (MAX_MSG_SIZE - 64)
#define MAX_LARGE_BLOB_SIZE    2048
#define TRANSPORT_TIME_LIMIT   (30 * 1000)

// ===== Type Definitions =====
typedef struct {
    uint8_t path[KEY_PATH_LEN];
    uint32_t purpose;
} key_path_config_t;

typedef struct {
    int fido_curve;
    mbedtls_ecp_group_id mbedtls_curve;
} curve_mapping_t;

typedef struct known_app {
    const uint8_t *rp_id_hash;
    const char *label;
    const bool *use_sign_count;
    const bool *use_self_attestation;
} known_app_t;

typedef struct pinUvAuthToken {
    uint8_t *data;
    size_t len;
    bool in_use;
    uint8_t permissions;
    uint8_t rp_id_hash[32];
    bool has_rp_id;
    bool user_present;
    bool user_verified;
} pinUvAuthToken_t;

// ===== Global Variables =====
extern pinUvAuthToken_t paut;
extern uint32_t user_present_time_limit;

// ===== Function Declarations =====
// Core Functions
void init_fido(void);
int scan_files(void);
int fido_process_apdu();
int fido_unload();

// Key Management
int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, 
               int curve, mbedtls_ecdsa_context *key);
int verify_key(const uint8_t *appId, const uint8_t *keyHandle, 
               mbedtls_ecdsa_context *key);
int fido_load_key(int curve, const uint8_t *cred_id, 
                  mbedtls_ecdsa_context *key);
int load_keydev(uint8_t *key);

// Crypto Operations
mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve);
int mbedtls_curve_to_fido(mbedtls_ecp_group_id id);
int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, 
            uint16_t in_len, uint8_t *out);
int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, 
            uint16_t in_len, uint8_t *out);
int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret);
int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, 
           uint16_t len, uint8_t *sign);
int cmd_get_random(void);

// User Interface
bool wait_button_pressed(void);
bool check_user_presence(void);

// State Management
bool getUserPresentFlagValue(void);
bool getUserVerifiedFlagValue(void);
void clearUserPresentFlag(void);
void clearUserVerifiedFlag(void);
void clearPinUvAuthTokenPermissionsExceptLbw(void);
uint32_t get_sign_counter(void);
uint8_t get_opts(void);
void set_opts(uint8_t);
void send_keepalive(void);

// Utility Functions
const known_app_t *find_app_by_rp_id_hash(const uint8_t *rp_id_hash);

#endif // _FIDO_H_
