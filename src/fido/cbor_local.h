#ifndef CBOR_LOCAL_H
#define CBOR_LOCAL_H

int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len);
int cbor_reset();
int cbor_get_info();
int cbor_make_credential(const uint8_t *data, size_t len);
int cbor_client_pin(const uint8_t *data, size_t len);
int cbor_get_assertion(const uint8_t *data, size_t len, bool next);
int cbor_get_next_assertion(const uint8_t *data, size_t len);
int cbor_selection();
int cbor_cred_mgmt(const uint8_t *data, size_t len);
int cbor_config(const uint8_t *data, size_t len);
int cbor_vendor(const uint8_t *data, size_t len);
int cbor_large_blobs(const uint8_t *data, size_t len);

#endif /* CBOR_LOCAL_H */
