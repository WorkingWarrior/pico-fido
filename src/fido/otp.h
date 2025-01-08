#ifndef OTP_H
#define OTP_H

#define FIXED_SIZE          16
#define KEY_SIZE            16
#define UID_SIZE            6
#define KEY_SIZE_OATH       20
#define ACC_CODE_SIZE       6

#define CONFIG1_VALID       0x01
#define CONFIG2_VALID       0x02
#define CONFIG1_TOUCH       0x04
#define CONFIG2_TOUCH       0x08
#define CONFIG_LED_INV      0x10
#define CONFIG_STATUS_MASK  0x1f

/* EXT Flags */
#define SERIAL_BTN_VISIBLE  0x01    // Serial number visible at startup (button press)
#define SERIAL_USB_VISIBLE  0x02    // Serial number visible in USB iSerial field
#define SERIAL_API_VISIBLE  0x04    // Serial number visible via API call
#define USE_NUMERIC_KEYPAD  0x08    // Use numeric keypad for digits
#define FAST_TRIG           0x10    // Use fast trig if only cfg1 set
#define ALLOW_UPDATE        0x20    // Allow update of existing configuration (selected flags + access code)
#define DORMANT             0x40    // Dormant config (woken up, flag removed, requires update flag)
#define LED_INV             0x80    // LED idle state is off rather than on
#define EXTFLAG_UPDATE_MASK (SERIAL_BTN_VISIBLE | SERIAL_USB_VISIBLE | SERIAL_API_VISIBLE | \
                             USE_NUMERIC_KEYPAD | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV)

/* TKT Flags */
#define TAB_FIRST       0x01    // Send TAB before first part
#define APPEND_TAB1     0x02    // Send TAB after first part
#define APPEND_TAB2     0x04    // Send TAB after second part
#define APPEND_DELAY1   0x08    // Add 0.5s delay after first part
#define APPEND_DELAY2   0x10    // Add 0.5s delay after second part
#define APPEND_CR       0x20    // Append CR as final character
#define OATH_HOTP       0x40    // OATH HOTP mode
#define CHAL_RESP       0x40    // Challenge-response enabled (both must be set)
#define PROTECT_CFG2    0x80    // Block update of config 2 unless config 2 is configured and has this bit set
#define TKTFLAG_UPDATE_MASK (TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_DELAY2 | \
                             APPEND_CR)

/* CFG Flags */
#define SEND_REF            0x01    // Send reference string (0..F) before data
#define PACING_10MS         0x04    // Add 10ms intra-key pacing
#define PACING_20MS         0x08    // Add 20ms intra-key pacing
#define STATIC_TICKET       0x20    // Static ticket generation
// Static
#define SHORT_TICKET        0x02    // Send truncated ticket (half length)
#define STRONG_PW1          0x10    // Strong password policy flag #1 (mixed case)
#define STRONG_PW2          0x40    // Strong password policy flag #2 (subtitute 0..7 to digits)
#define MAN_UPDATE          0x80    // Allow manual (local) update of static OTP
// Challenge (no keyboard)
#define HMAC_LT64           0x04    // Set when HMAC message is less than 64 bytes
#define CHAL_BTN_TRIG       0x08    // Challenge-response operation requires button press
#define CHAL_YUBICO         0x20    // Challenge-response enabled - Yubico OTP mode
#define CHAL_HMAC           0x22    // Challenge-response enabled - HMAC-SHA1
// OATH
#define OATH_HOTP8          0x02    // Generate 8 digits HOTP rather than 6 digits
#define OATH_FIXED_MODHEX1  0x10    // First byte in fixed part sent as modhex
#define OATH_FIXED_MODHEX2  0x40    // First two bytes in fixed part sent as modhex
#define OATH_FIXED_MODHEX   0x50    // Fixed part sent as modhex
#define OATH_FIXED_MASK     0x50    // Mask to get out fixed flags
#define CFGFLAG_UPDATE_MASK (PACING_10MS | PACING_20MS)

PACK(
typedef struct otp_config {
    uint8_t fixed_data[FIXED_SIZE];
    uint8_t uid[UID_SIZE];
    uint8_t aes_key[KEY_SIZE];
    uint8_t acc_code[ACC_CODE_SIZE];
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
    uint8_t rfu[2];
    uint16_t crc;
}) otp_config_t;

#define otp_config_size sizeof(otp_config_t)

uint16_t otp_status();
int otp_process_apdu();
int otp_unload();

#endif /* OTP_H */
