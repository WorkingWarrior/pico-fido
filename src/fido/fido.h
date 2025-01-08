/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _FIDO_H_
#define _FIDO_H_

// Platform-specific includes
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

// Key and path definitions
#define CTAP_PUBKEY_LEN          (65)
#define KEY_PATH_LEN             (32)
#define KEY_PATH_ENTRIES         (KEY_PATH_LEN / sizeof(uint32_t))
#define SHA256_DIGEST_LENGTH     (32)
#define KEY_HANDLE_LEN           (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)

// Key configuration
#define FIDO_KEY_PURPOSE       10022
#define HARDENED_BIT           0x80000000
#define KEY_ENTRIES_START      1

// FIDO2 Algorithms
#define FIDO2_ALG_ES256        -7    // ECDSA-SHA256 P256
#define FIDO2_ALG_EDDSA        -8    // EdDSA
#define FIDO2_ALG_ES384        -35   // ECDSA-SHA384 P384
#define FIDO2_ALG_ES512        -36   // ECDSA-SHA512 P521
#define FIDO2_ALG_ECDH_ES_HKDF_256  -25   // ECDH-ES + HKDF-256
#define FIDO2_ALG_ES256K       -47
#define FIDO2_ALG_RS256        -257
#define FIDO2_ALG_RS384        -258
#define FIDO2_ALG_RS512        -259

// FIDO2 Curves
#define FIDO2_CURVE_P256       1
#define FIDO2_CURVE_P384       2
#define FIDO2_CURVE_P521       3
#define FIDO2_CURVE_X25519     4
#define FIDO2_CURVE_X448       5
#define FIDO2_CURVE_ED25519    6
#define FIDO2_CURVE_ED448      7
#define FIDO2_CURVE_P256K1     8

// Authentication flags
#define FIDO2_AUT_FLAG_UP      0x1
#define FIDO2_AUT_FLAG_UV      0x4
#define FIDO2_AUT_FLAG_AT      0x40
#define FIDO2_AUT_FLAG_ED      0x80

// Options
#define FIDO2_OPT_EA          0x01   // Enterprise Attestation

// Limits and constraints
#define MAX_PIN_RETRIES              8
#define MAX_CREDENTIAL_COUNT_IN_LIST  16
#define MAX_CRED_ID_LENGTH           1024
#define MAX_RESIDENT_CREDENTIALS     256
#define MAX_CREDBLOB_LENGTH          128
#define MAX_MSG_SIZE                 1024
#define MAX_FRAGMENT_LENGTH          (MAX_MSG_SIZE - 64)
#define MAX_LARGE_BLOB_SIZE          2048
#define TRANSPORT_TIME_LIMIT         (30 * 1000)  // USB

// Data structures
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

// Global variables
extern pinUvAuthToken_t paut;
extern uint32_t user_present_time_limit;

// Function declarations
extern int scan_files(void);
extern int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, 
                     int curve, mbedtls_ecdsa_context *key);
extern int verify_key(const uint8_t *appId, const uint8_t *keyHandle, 
                     mbedtls_ecdsa_context *key);
extern bool wait_button_pressed(void);
extern void init_fido(void);
extern mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve);
extern int mbedtls_curve_to_fido(mbedtls_ecp_group_id id);
extern int fido_load_key(int curve, const uint8_t *cred_id, 
                        mbedtls_ecdsa_context *key);
extern int load_keydev(uint8_t *key);
extern int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, 
                  uint16_t in_len, uint8_t *out);
extern int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, 
                  uint16_t in_len, uint8_t *out);
extern int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret);
extern int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, 
                 uint16_t len, uint8_t *sign);

// Flag management functions
extern bool getUserPresentFlagValue(void);
extern bool getUserVerifiedFlagValue(void);
extern void clearUserPresentFlag(void);
extern void clearUserVerifiedFlag(void);
extern void clearPinUvAuthTokenPermissionsExceptLbw(void);
extern void send_keepalive(void);
extern uint32_t get_sign_counter(void);
extern uint8_t get_opts(void);
extern void set_opts(uint8_t);
extern bool check_user_presence(void);
extern const known_app_t *find_app_by_rp_id_hash(const uint8_t *rp_id_hash);

#endif // _FIDO_H_
