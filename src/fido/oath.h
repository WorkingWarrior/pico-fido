#ifndef OATH_H
#define OATH_H

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8
#define MAX_OTP_COUNTER 3

#define TAG_NAME            0x71
#define TAG_NAME_LIST       0x72
#define TAG_KEY             0x73
#define TAG_CHALLENGE       0x74
#define TAG_RESPONSE        0x75
#define TAG_T_RESPONSE      0x76
#define TAG_NO_RESPONSE     0x77
#define TAG_PROPERTY        0x78
#define TAG_T_VERSION       0x79
#define TAG_IMF             0x7A
#define TAG_ALGO            0x7B
#define TAG_TOUCH_RESPONSE  0x7C
#define TAG_PASSWORD        0x80
#define TAG_NEW_PASSWORD    0x81
#define TAG_PIN_COUNTER     0x82

#define ALG_HMAC_SHA1       0x01
#define ALG_HMAC_SHA256     0x02
#define ALG_HMAC_SHA512     0x03
#define ALG_MASK            0x0F

#define OATH_TYPE_HOTP      0x10
#define OATH_TYPE_TOTP      0x20
#define OATH_TYPE_MASK      0xF0

#define PROP_INC            0x01
#define PROP_TOUCH          0x02

int oath_process_apdu();
int oath_unload();

#endif /* OATH_H */
