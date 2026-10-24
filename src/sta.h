// 802.11 station join (probe, open auth, association) and data-frame RX/TX plumbing on top of tx.c / rx.c.
#ifndef STA_H
#define STA_H
#include <stdint.h>
#include "rtl.h"
#include "rx.h"

typedef struct {
    uint8_t mac[6], bssid[6];
    char ssid[33];
    int have_bssid;            // bssid known/required
    int channel;
    // learned from probe response / beacon
    int ap_seen;
    uint16_t ap_cap;
    uint8_t rates[16]; int nrates;      // supported rates IE body (raw, with basic bit)
    uint8_t xrates[16]; int nxrates;    // extended supported rates IE body
    uint8_t rsn[64]; int rsn_len;       // full RSN IE incl. id+len (0 if none)
    int rssi;
    // join result
    int aid, last_status;
    int associated;
    // events
    int deauth_seen, deauth_reason, disassoc_seen, disassoc_reason;
    unsigned long data_rx, prot_rx, prot_extiv, eapol_rx, group_rx;
    int eapol_keyinfo;                  // last EAPOL-Key info (-1 none)
    // internal
    rtl_t *r;
    int rate;                           // mgmt TX rate (Mbps*10)
    int auth_status, auth_got, assoc_got, assoc_status;
    uint8_t last_hdr_dummy;
} sta_t;

// frame (FCS stripped) is a data frame for us: from-DS from our BSSID, addr1 == our MAC or group. hdr intact.
typedef void (*sta_data_cb)(void *ud, const uint8_t *frame, int len, const rtl_frame_t *f);

void sta_init(sta_t *s, rtl_t *r, const char *ssid, const uint8_t *bssid, int channel);
// Each returns 0 on success, nonzero failure (s->last_status holds the 802.11 status code when the AP refused, else -1 = timeout).
int  sta_scan(sta_t *s, int timeout_ms);
int  sta_auth(sta_t *s);
int  sta_assoc(sta_t *s);
// Process RX for up to ms; delivers matching data frames to cb (may be NULL). Updates counters/deauth state.
void sta_poll(sta_t *s, int ms, sta_data_cb cb, void *ud);
int  sta_send_null(sta_t *s);
// Send a to-DS data frame: dst=DA, payload = LLC/SNAP + packet (or pre-encrypted body incl. CCMP header when prot=1).
int  sta_send_data(sta_t *s, const uint8_t dst[6], const uint8_t *body, int blen, int prot, int rate);
#endif
