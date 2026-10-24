// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wps.h - Wi-Fi Protected Setup (WPS 2.0) ENROLLEE: PBC and PIN registration protocol, independent of USB.
 * Apple CommonCrypto only (SHA-256, HMAC, AES-128-CBC); the 1536-bit DH is src/bignum_dh.c. Pure functions and one
 * state machine; no sockets, no timers, no device. See docs/WPS.md for the integration steps and the security note.
 *
 * Layers (use the top one; the lower ones are exposed for tests and for callers that frame EAPOL themselves):
 *   wps_eap_t       EAPOL/EAP-WSC framing, fragmentation, retransmit  (feed it received EAPOL frames)
 *   wps_enrollee_t  M1..M8 / ACK / NACK / Done messages              (feed it raw WSC message bodies)
 *   TLV, KDF, PIN, encrypted-settings primitives
 * Not a registrar: there is no code to hand out credentials or to guess PINs. */
#ifndef WPS_H
#define WPS_H
#include <stddef.h>
#include <stdint.h>

/* ---- attribute types (WSC 2.0 table 28) ---- */
#define WPS_ATTR_ASSOC_STATE      0x1002
#define WPS_ATTR_AUTH_TYPE        0x1003
#define WPS_ATTR_AUTH_FLAGS       0x1004
#define WPS_ATTR_AUTHENTICATOR    0x1005
#define WPS_ATTR_CONFIG_METHODS   0x1008
#define WPS_ATTR_CONFIG_ERROR     0x1009
#define WPS_ATTR_CONN_TYPE_FLAGS  0x100D
#define WPS_ATTR_CRED             0x100E
#define WPS_ATTR_ENCR_TYPE        0x100F
#define WPS_ATTR_ENCR_FLAGS       0x1010
#define WPS_ATTR_DEV_NAME         0x1011
#define WPS_ATTR_DEV_PWID         0x1012
#define WPS_ATTR_E_HASH1          0x1014
#define WPS_ATTR_E_HASH2          0x1015
#define WPS_ATTR_E_SNONCE1        0x1016
#define WPS_ATTR_E_SNONCE2        0x1017
#define WPS_ATTR_ENCR_SETTINGS    0x1018
#define WPS_ATTR_ENROLLEE_NONCE   0x101A
#define WPS_ATTR_KWA              0x101E
#define WPS_ATTR_MAC              0x1020
#define WPS_ATTR_MANUFACTURER     0x1021
#define WPS_ATTR_MSG_TYPE         0x1022
#define WPS_ATTR_MODEL_NAME       0x1023
#define WPS_ATTR_MODEL_NUMBER     0x1024
#define WPS_ATTR_NET_INDEX        0x1026
#define WPS_ATTR_NET_KEY          0x1027
#define WPS_ATTR_NET_KEY_INDEX    0x1028
#define WPS_ATTR_OS_VERSION       0x102D
#define WPS_ATTR_PUBLIC_KEY       0x1032
#define WPS_ATTR_REGISTRAR_NONCE  0x1039
#define WPS_ATTR_REQUEST_TYPE     0x103A
#define WPS_ATTR_RESPONSE_TYPE    0x103B
#define WPS_ATTR_RF_BANDS         0x103C
#define WPS_ATTR_R_HASH1          0x103D
#define WPS_ATTR_R_HASH2          0x103E
#define WPS_ATTR_R_SNONCE1        0x103F
#define WPS_ATTR_R_SNONCE2        0x1040
#define WPS_ATTR_SELECTED_REG     0x1041
#define WPS_ATTR_SERIAL           0x1042
#define WPS_ATTR_WPS_STATE        0x1044
#define WPS_ATTR_SSID             0x1045
#define WPS_ATTR_UUID_E           0x1047
#define WPS_ATTR_UUID_R           0x1048
#define WPS_ATTR_VENDOR_EXT       0x1049
#define WPS_ATTR_VERSION          0x104A
#define WPS_ATTR_SELREG_METHODS   0x1053
#define WPS_ATTR_PRIMARY_DEVTYPE  0x1054
#define WPS_ATTR_AP_SETUP_LOCKED  0x1057

/* message types */
#define WPS_MSG_M1   4
#define WPS_MSG_M2   5
#define WPS_MSG_M2D  6
#define WPS_MSG_M3   7
#define WPS_MSG_M4   8
#define WPS_MSG_M5   9
#define WPS_MSG_M6   10
#define WPS_MSG_M7   11
#define WPS_MSG_M8   12
#define WPS_MSG_ACK  13
#define WPS_MSG_NACK 14
#define WPS_MSG_DONE 15

/* device password ids, config errors (WSC 2.0 table 30), auth / encryption flags */
#define WPS_DEVPW_PIN 0x0000
#define WPS_DEVPW_PBC 0x0004
#define WPS_CFG_NO_ERROR            0
#define WPS_CFG_DECRYPTION_FAILURE  2
#define WPS_CFG_MULTIPLE_PBC        12
#define WPS_CFG_SETUP_LOCKED        15
#define WPS_CFG_MSG_TIMEOUT         16
#define WPS_CFG_SESSION_TIMEOUT     17
#define WPS_CFG_PIN_AUTH_FAILURE    18
#define WPS_AUTH_OPEN   0x0001
#define WPS_AUTH_WPAPSK 0x0002
#define WPS_AUTH_SHARED 0x0004
#define WPS_AUTH_WPA    0x0008
#define WPS_AUTH_WPA2   0x0010
#define WPS_AUTH_WPA2PSK 0x0020
#define WPS_ENCR_NONE 0x0001
#define WPS_ENCR_WEP  0x0002
#define WPS_ENCR_TKIP 0x0004
#define WPS_ENCR_AES  0x0008

#define WPS_MAX_MSG 2048            /* longest WSC message body we accept or build */
#define WPS_PIN_MAX 8

/* return codes (functions that return a length return >= 0 on success) */
#define WPS_ERR_BAD    (-1)         /* malformed / failed verification (no reply produced) */
#define WPS_ERR_IGNORE (-2)         /* not for this session or not expected now: dropped, state unchanged */
#define WPS_ERR_STATE  (-3)
#define WPS_ERR_SPACE  (-4)         /* output buffer too small */
#define WPS_ERR_PIN    (-5)         /* PIN not 4 or 8 digits, or bad checksum */
#define WPS_ERR_KEY    (-6)         /* DH public key invalid */

/* ---- TLV ---- */
typedef struct { uint8_t *p; size_t cap, len; int err; } wps_buf_t;
void wps_buf_init(wps_buf_t *b, uint8_t *p, size_t cap);
void wps_put(wps_buf_t *b, uint16_t type, const void *v, size_t n);
void wps_put8(wps_buf_t *b, uint16_t type, uint8_t v);
void wps_put16(wps_buf_t *b, uint16_t type, uint16_t v);
void wps_put_vendor_v2(wps_buf_t *b);                    /* WFA vendor extension carrying Version2 = 2.0 */
int wps_tlv_check(const uint8_t *buf, size_t len);       /* 0 if the attribute list is well formed */
const uint8_t *wps_tlv_find(const uint8_t *buf, size_t len, uint16_t type, size_t *vlen); /* first match or NULL */
int wps_tlv_get(const uint8_t *buf, size_t len, uint16_t type, void *out, size_t want);   /* exact length; 0 / -1 */
int wps_tlv_get16(const uint8_t *buf, size_t len, uint16_t type, uint16_t *out);
int wps_tlv_get8(const uint8_t *buf, size_t len, uint16_t type, uint8_t *out);

/* ---- PIN ---- */
int wps_pin_checksum(uint32_t pin7);                     /* check digit (0-9) for a 7-digit number */
int wps_pin_valid(const char *pin);                      /* 1: 8 digits with right checksum, or 4 digits; else 0 */
int wps_pin_generate(uint32_t seven, char out[9]);       /* "NNNNNNNC"; seven < 10000000; 0 ok. Caller supplies randomness */

/* ---- keys ---- */
typedef struct { uint8_t auth[32], kwk[16], emsk[32]; } wps_keys_t;
void wps_kdk(const uint8_t dhkey[32], const uint8_t n1[16], const uint8_t mac_e[6], const uint8_t n2[16], uint8_t kdk[32]);
void wps_kdf(const uint8_t kdk[32], uint8_t *out, size_t outlen);        /* WPS KDF, label "Wi-Fi Easy and Secure Key Derivation" */
/* shared = 192-byte DH result; DHKey = SHA-256(shared) */
void wps_derive_keys(const uint8_t shared[192], const uint8_t n1[16], const uint8_t mac_e[6], const uint8_t n2[16], wps_keys_t *k);
void wps_psk(const uint8_t authkey[32], const char *pin, uint8_t psk1[16], uint8_t psk2[16]);
/* E-Hash1/2 and R-Hash1/2: HMAC(AuthKey, snonce || psk || PKe || PKr) */
void wps_hash(const uint8_t authkey[32], const uint8_t snonce[16], const uint8_t psk[16], const uint8_t pke[192],
              const uint8_t pkr[192], uint8_t out[32]);
/* Authenticator attribute value: first 8 bytes of HMAC(AuthKey, prev || cur) */
void wps_authenticator(const uint8_t authkey[32], const uint8_t *prev, size_t prev_len, const uint8_t *cur, size_t cur_len, uint8_t out[8]);
/* Encrypted Settings: out = IV(16) || AES-128-CBC(KeyWrapKey, plain || KWA attribute) with PKCS padding. Returns length. */
int wps_encr_seal(const wps_keys_t *k, const uint8_t iv[16], const uint8_t *plain, size_t plen, uint8_t *out, size_t cap);
/* Decrypts and checks padding and the Key Wrap Authenticator. Returns plaintext length (KWA stripped) or WPS_ERR_BAD. */
int wps_encr_open(const wps_keys_t *k, const uint8_t *in, size_t len, uint8_t *plain, size_t cap);
void wps_uuid_from_mac(const uint8_t mac[6], uint8_t uuid[16]);

/* ---- credential the registrar hands over (M8) ---- */
typedef struct {
    uint8_t ssid[32]; size_t ssid_len;
    uint16_t auth_type;           /* WPS_AUTH_*: 0x0001 open, 0x0022 = WPA-PSK + WPA2-PSK mixed ... */
    uint16_t encr_type;           /* WPS_ENCR_*: 0x0001 none, 0x0008 AES, 0x000C TKIP+AES ... */
    uint8_t key[65]; size_t key_len; /* passphrase (8..63) or 64 hex digits (raw PSK) or WEP key; NUL-terminated */
    int key_is_hex_psk;           /* key_len == 64 and all hex digits */
    int key_index;                /* WEP key index, default 1 */
    uint8_t mac[6];               /* registrar's idea of the network MAC (often the BSSID) */
} wps_cred_t;

/* ---- enrollee ---- */
typedef struct {
    uint8_t mac[6];               /* our station MAC (goes into M1, and into the key derivation) */
    uint8_t uuid[16];             /* UUID-E; wps_uuid_from_mac() if you have none */
    const char *pin;              /* NULL = push button (PBC, password "00000000"); else 4 or 8 digits */
    const char *manufacturer, *model_name, *model_number, *serial, *device_name; /* NULL = ALFA / AWUS036ACS / ... */
    void (*rand_fn)(uint8_t *buf, size_t n);   /* NULL = arc4random_buf */
    size_t frag_size;             /* EAP-WSC fragment payload, 0 = 1398 */
} wps_cfg_t;

typedef enum { WPS_ST_IDLE, WPS_ST_WAIT_M2, WPS_ST_WAIT_M4, WPS_ST_WAIT_M6, WPS_ST_WAIT_M8,
               WPS_ST_M2D, WPS_ST_DONE, WPS_ST_FAILED } wps_state_t;
typedef enum { WPS_FAIL_NONE, WPS_FAIL_BAD_MSG, WPS_FAIL_AUTHENTICATOR, WPS_FAIL_DECRYPT, WPS_FAIL_PIN_AUTH,
               WPS_FAIL_PWID_MISMATCH, WPS_FAIL_AP_NACK, WPS_FAIL_BAD_KEY, WPS_FAIL_EAP_FAILURE,
               WPS_FAIL_BAD_CRED } wps_fail_t;

typedef struct {
    wps_cfg_t cfg;
    char pin[WPS_PIN_MAX + 1], manufacturer[65], model_name[33], model_number[33], serial[33], device_name[33];
    int pbc;                      /* push-button mode (password id 4, PIN "00000000") */
    wps_state_t state;
    wps_fail_t fail;              /* why, when state == WPS_ST_FAILED */
    uint16_t cfg_error;           /* config error we sent in our NACK, or the AP's NACK value (WPS_CFG_*) */
    wps_cred_t cred;              /* valid when state == WPS_ST_DONE */
    int have_cred;
    /* internals */
    uint8_t priv[192], pke[192], pkr[192], ne[16], nr[16];
    wps_keys_t keys;
    uint8_t psk1[16], psk2[16], es1[16], es2[16], rhash1[32], rhash2[32];
    uint8_t prev[WPS_MAX_MSG]; size_t prev_len;
} wps_enrollee_t;

int wps_enrollee_init(wps_enrollee_t *e, const wps_cfg_t *cfg);   /* 0, WPS_ERR_PIN */
/* Build M1. Returns length. */
int wps_enrollee_start(wps_enrollee_t *e, uint8_t *out, size_t cap);
/* Process one received WSC message body. Returns the length of the reply written to out (0 = none), or a WPS_ERR_*.
 * On a protocol failure the reply is our WSC_NACK and e->state becomes WPS_ST_FAILED (e->fail / e->cfg_error say why).
 * M2D produces a WSC_ACK and state WPS_ST_M2D ("registrar not ready": no PBC window / PIN not entered). */
int wps_enrollee_rx(wps_enrollee_t *e, const uint8_t *in, size_t len, uint8_t *out, size_t cap);
void wps_enrollee_clear(wps_enrollee_t *e);                         /* zero all secrets */

/* ---- EAPOL / EAP-WSC ---- */
#define WPS_EAP_MAX_FRAME 1700
#define WPS_OP_START 1
#define WPS_OP_ACK   2
#define WPS_OP_NACK  3
#define WPS_OP_MSG   4
#define WPS_OP_DONE  5
#define WPS_OP_FRAG_ACK 6
#define WPS_FLAG_LEN  0x01
#define WPS_FLAG_MORE 0x02

typedef struct {
    wps_enrollee_t en;
    size_t frag_size;
    uint8_t rx[WPS_MAX_MSG]; size_t rx_len, rx_total; int rx_active;
    uint8_t tx[WPS_MAX_MSG]; size_t tx_len, tx_off; uint8_t tx_op;
    int have_id; uint8_t last_id;
    uint8_t last_resp[WPS_EAP_MAX_FRAME]; size_t last_resp_len;
} wps_eap_t;

int wps_eap_init(wps_eap_t *s, const wps_cfg_t *cfg);
/* EAPOL-Start frame to send after associating (4 bytes). Returns 4. */
int wps_eap_start_frame(uint8_t *out, size_t cap);
/* Feed one received EAPOL frame (starting at the EAPOL header, no 802.11/LLC). Returns the length of ONE EAPOL frame to
 * send in reply (0 = nothing), or < 0. Call again for every received frame; every reply is one frame, a fragmented
 * message is continued by the AP's fragment ACKs. Retransmitted requests (same EAP id) get the same reply again. */
int wps_eap_rx(wps_eap_t *s, const uint8_t *eapol, size_t len, uint8_t *out, size_t cap);
/* 1 = credential received and WSC_Done sent, 0 = in progress (or waiting after M2D), -1 = failed (s->en.fail) */
int wps_eap_result(const wps_eap_t *s);
void wps_eap_clear(wps_eap_t *s);
/* frame builders / parser shared with the AP side of the tests */
int wps_eap_build(uint8_t *out, size_t cap, int code, uint8_t id, int op, uint8_t flags, int have_msglen, uint16_t msglen,
                  const uint8_t *data, size_t dlen);   /* EAPOL header + EAP expanded type WFA/1 + op/flags/[len]/data */
int wps_eap_build_identity(uint8_t *out, size_t cap, int code, uint8_t id, const char *identity);

/* ---- probe request / association request IEs (enrollee side) ---- */
/* Whole vendor IE (dd len 00:50:f2:04 + attributes). PBC when cfg->pin == NULL (password id 4) else PIN (id 0). */
int wps_build_probe_req_ie(const wps_cfg_t *cfg, uint8_t *out, size_t cap);
int wps_build_assoc_req_ie(uint8_t *out, size_t cap);   /* Version, Request Type, Version2. Associate WITHOUT an RSN IE. */

/* ---- AP's WSC IE in Beacon / Probe Response ---- */
typedef struct {
    int present;                  /* a WSC IE was found */
    uint8_t version, version2;    /* 0x10 ; 0x20 for WPS 2.0 (0 if absent) */
    int wps_state;                /* 1 not configured, 2 configured, 0 absent */
    int ap_setup_locked;
    int selected_registrar;       /* a registrar is active (PBC pressed / PIN entered) */
    uint16_t dev_pwid;            /* with selected_registrar: 4 = PBC, 0/other = PIN */
    uint16_t selreg_methods, cfg_methods;
    int have_uuid; uint8_t uuid[16];
    char device_name[33], manufacturer[33], model_name[33];
    uint8_t bssid[6];             /* caller fills (from the frame header) */
} wps_ap_info_t;
/* ies = the IE bytes of a Beacon/Probe Response (tagged parameters). Joins WSC IEs split over several elements.
 * Returns 1 if a WSC IE was found, 0 if none, -1 if malformed. */
int wps_ap_parse(const uint8_t *ies, size_t len, wps_ap_info_t *out);

typedef enum { WPS_AP_OK, WPS_AP_NO_WPS, WPS_AP_LOCKED, WPS_AP_PBC_INACTIVE, WPS_AP_PIN_WRONG_MODE } wps_ap_reason_t;
typedef enum { WPS_MODE_PBC, WPS_MODE_PIN } wps_mode_t;
wps_ap_reason_t wps_ap_check(const wps_ap_info_t *ap, wps_mode_t mode);
const char *wps_ap_reason_str(wps_ap_reason_t r);
/* Among scanned APs: index of the single AP with an active PBC window; -1 none; -2 session overlap (two or more
 * different registrars in PBC mode: do not start, report WPS_CFG_MULTIPLE_PBC). BSSIDs with the same UUID (2.4/5 GHz of
 * one router) count once; locked APs are skipped. *count (may be NULL) = number of distinct active registrars. */
int wps_pbc_pick(const wps_ap_info_t *aps, size_t n, int *count);

/* ---- self rate limit, per BSSID (the caller keeps one per AP) ---- */
typedef struct { int fails; int blocked; uint64_t next_ok; } wps_limiter_t;
/* 0 = go ahead; > 0 = seconds to wait; -1 = blocked until wps_limiter_reset (too many failures) */
int64_t wps_limiter_check(const wps_limiter_t *l, uint64_t now_sec);
void wps_limiter_record(wps_limiter_t *l, uint64_t now_sec, int success);   /* delay 30 s, doubling, max 1 h; blocked after 5 */
void wps_limiter_reset(wps_limiter_t *l);
#endif
