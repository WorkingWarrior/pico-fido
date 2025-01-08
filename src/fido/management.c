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

#include "fido.h"
#include "pico_keys.h"
#include "apdu.h"
#include "version.h"
#include "files.h"
#include "asn1.h"
#include "management.h"
#include "random.h"

/* Forward declarations */
extern int cbor_reset(void);

/* Constants */
#define INS_READ_CONFIG    0x1D
#define INS_WRITE_CONFIG   0x1C
#define INS_RESET         0x1E    // Reset device
#define INS_GET_RANDOM    0x04    // Get random data

static const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { INS_GET_RANDOM, cmd_get_random },
    { 0x00, NULL }
};

/* Management initialization */
INITIALIZER(man_ctor) {
    register_app(man_select, man_aid);
}

/* Core management functions */
int man_select(app_t *a, uint8_t force) {
    if (!a) {
        return PICOKEY_ERR_INVALID_PARAMETER;
    }

    // Setup application handlers
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;

    // Generate version string response
    sprintf((char *)res_APDU, "%d.%d.0", 
            PICO_FIDO_VERSION_MAJOR, 
            PICO_FIDO_VERSION_MINOR);
    res_APDU_size = strlen((char *)res_APDU);
    apdu.ne = res_APDU_size;

    // Initialize if forced
    if (force) {
        scan_all();
        init_otp();
    }

    return PICOKEY_OK;
}

int cmd_get_random() {
    // Sprawdź czy długość żądanych danych jest prawidłowa
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_WRONG_P1P2();
    }

    // Sprawdź czy żądana długość nie przekracza maksymalnej
    if (apdu.ne > MAX_RANDOM_BUFFER) {
        return SW_WRONG_LENGTH();
    }

    // Generuj losowe dane
    const uint8_t *random_data = random_bytes_get(apdu.ne);
    if (!random_data) {
        return SW_EXEC_ERROR(); 
    }

    // Kopiuj do bufora odpowiedzi
    memcpy(res_APDU, random_data, apdu.ne);
    res_APDU_size = apdu.ne;

    // Zwolnij bufor z losowymi danymi
    random_bytes_free(random_data);

    return SW_OK();
}

int man_unload(void) {
    return PICOKEY_OK;
}

/* APDU command processing */
int man_process_apdu(void) {
    // Verify CLA
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }

    // Find and execute command handler
    for (const cmd_t *cmd = cmds; cmd->cmd_handler != NULL; cmd++) {
        if (cmd->ins == INS(apdu)) {
            return cmd->cmd_handler();
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

/* Capability checking */
bool cap_supported(uint16_t cap) {
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    if (!file_has_data(ef)) {
        return true;
    }

    uint16_t tag = 0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    asn1_ctx_t ctxi;

    asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag == TAG_USB_ENABLED) {
            uint16_t ecaps = tag_data[0];
            if (tag_len == 2) {
                ecaps = (tag_data[0] << 8) | tag_data[1];
            }
            return ecaps & cap;
        }
    }
    return true;
}

/* Configuration management */
int man_get_config(void) {
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    res_APDU_size = 0;

    // Start building response
    res_APDU[res_APDU_size++] = 0; // Overall length (filled later)

    // Add USB support info
    res_APDU[res_APDU_size++] = TAG_USB_SUPPORTED;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = CAP_FIDO2 >> 8;
    res_APDU[res_APDU_size++] = CAP_OTP | CAP_U2F | CAP_OATH;

    // Add serial number
    res_APDU[res_APDU_size++] = TAG_SERIAL;
    res_APDU[res_APDU_size++] = 4;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, 4);
    res_APDU_size += 4;

    // Add form factor
    res_APDU[res_APDU_size++] = TAG_FORM_FACTOR;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;

    // Add version info
    res_APDU[res_APDU_size++] = TAG_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;

    // Add NFC support info
    res_APDU[res_APDU_size++] = TAG_NFC_SUPPORTED;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;

    // Add default or existing configuration
    if (!file_has_data(ef)) {
        // Add default configuration
        res_APDU[res_APDU_size++] = TAG_USB_ENABLED;
        res_APDU[res_APDU_size++] = 2;
        res_APDU[res_APDU_size++] = CAP_FIDO2 >> 8;
        res_APDU[res_APDU_size++] = CAP_OTP | CAP_U2F | CAP_OATH;

        res_APDU[res_APDU_size++] = TAG_DEVICE_FLAGS;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = FLAG_EJECT;

        res_APDU[res_APDU_size++] = TAG_CONFIG_LOCK;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = 0x00;

        res_APDU[res_APDU_size++] = TAG_NFC_ENABLED;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = 0x00;
    }
    else {
        // Add existing configuration
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), file_get_size(ef));
        res_APDU_size += file_get_size(ef);
    }

    // Update overall length
    res_APDU[0] = (uint8_t)(res_APDU_size - 1);
    return 0;
}

/* Command handlers */
int cmd_read_config(void) {
    man_get_config();
    return SW_OK();
}

int cmd_write_config(void) {
    if (apdu.data[0] != apdu.nc - 1) {
        return SW_WRONG_DATA();
    }

    file_t *ef = file_new(EF_DEV_CONF);
    file_put_data(ef, apdu.data + 1, (uint16_t)(apdu.nc - 1));
    low_flash_available();
    return SW_OK();
}

int cmd_factory_reset(void) {
    cbor_reset();
    return SW_OK();
}
