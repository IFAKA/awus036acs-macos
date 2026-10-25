// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_link_wps.c - the WPS enrollee run (src/wpslink.c: probe, OPEN association with the WSC IE, EAPOL-Start, EAP-WSC M1..M8,
 * Done, leave) against a fake AP + the in-test registrar (src/wps_testreg.h) in the same process.
 *
 * THIS IS A SOFTWARE LOOPBACK, NOT AN AIR TEST. No radio, no real router: sta_io hooks replace the USB transmit / receive. It
 * proves the call sequence and framing in wpslink.c / sta.c; it can NOT prove interoperability with a real WPS router, and no
 * PBC / PIN run was ever made against one.
 *
 * Build / run: make test-link-wps */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "wpslink.h"
#include "sta.h"
static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)
#include "wps_testreg.h"


#define QN 64
typedef struct { uint8_t d[700]; int n; } qf_t;
static struct {
    qf_t q[QN]; int qh, qt;
    uint8_t bssid[6], sta[6];
    int locked, sel, pwid;                  /* beacon WSC state */
    size_t frag;
    reg_t *reg;
    uint8_t id;
    int probes, auths, assocs, assoc_wsc, assoc_rsn, starts, deauths, frames_rx, done_seen;
    uint8_t rx[WPS_MAX_MSG]; size_t rx_have; int rx_op;
    uint8_t tx[WPS_MAX_MSG]; size_t tx_n, tx_off; int tx_op;
} ap;
static reg_t REG;

static const uint8_t LLC_EAPOL[8] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8E};

static void qpush(const uint8_t *f, int n)
{
    qf_t *e = &ap.q[ap.qt % QN];
    memcpy(e->d, f, n); e->n = n; ap.qt++;
}
static void mkhdr(uint8_t *h, uint8_t fc0, uint8_t fc1)
{
    memset(h, 0, 24);
    h[0] = fc0; h[1] = fc1;
    memcpy(h + 4, ap.sta, 6); memcpy(h + 10, ap.bssid, 6); memcpy(h + 16, ap.bssid, 6);
}
static void send_mgmt(uint8_t fc0, const uint8_t *body, int bl)
{
    uint8_t f[700]; mkhdr(f, fc0, 0); memcpy(f + 24, body, bl); qpush(f, 24 + bl);
}
static void send_eapol(const uint8_t *e, int n)
{
    uint8_t f[700]; mkhdr(f, 0x08, 0x02);
    memcpy(f + 24, LLC_EAPOL, 8); memcpy(f + 32, e, n); qpush(f, 32 + n);
}

static void ap_probe_resp(void)
{
    uint8_t b[400], a[200]; int n = 8;
    wps_buf_t w; wps_buf_init(&w, a, sizeof a);
    wps_put8(&w, WPS_ATTR_VERSION, 0x10); wps_put8(&w, WPS_ATTR_WPS_STATE, 2);
    wps_put8(&w, WPS_ATTR_AP_SETUP_LOCKED, (uint8_t)ap.locked);
    wps_put8(&w, WPS_ATTR_SELECTED_REG, (uint8_t)ap.sel);
    if (ap.sel) { wps_put16(&w, WPS_ATTR_DEV_PWID, (uint16_t)ap.pwid); wps_put16(&w, WPS_ATTR_SELREG_METHODS, 0x0188); }
    wps_put(&w, WPS_ATTR_UUID_E, "0123456789abcdef", 16);
    wps_put_vendor_v2(&w);
    memset(b, 0, 8);
    b[n++] = 0x64; b[n++] = 0; b[n++] = 0x11; b[n++] = 0x04;               /* ESS + privacy */
    b[n++] = 0; b[n++] = 7; memcpy(b + n, "LoopNet", 7); n += 7;
    memcpy(b + n, "\x01\x04\x82\x84\x8b\x96", 6); n += 6;
    memcpy(b + n, "\x03\x01\x06", 3); n += 3;
    b[n++] = 0xDD; b[n++] = (uint8_t)(4 + w.len); memcpy(b + n, "\x00\x50\xF2\x04", 4); memcpy(b + n + 4, a, w.len); n += 4 + (int)w.len;
    send_mgmt(0x50, b, n);
}

static const uint8_t *find_ie(const uint8_t *p, int len, int id)
{
    const uint8_t *e = p + len;
    while (p + 2 <= e && p + 2 + p[1] <= e) { if (p[0] == id) return p; p += 2 + p[1]; }
    return NULL;
}

/* AP -> STA: next fragment of ap.tx (a registrar message); sets MORE and the total length on the first one */
static void ap_send_next_frag(void)
{
    uint8_t f[WPS_EAP_MAX_FRAME];
    size_t rem = ap.tx_n - ap.tx_off, chunk = rem > ap.frag ? ap.frag : rem;
    int first = ap.tx_off == 0 && rem > ap.frag;
    int fl = wps_eap_build(f, sizeof f, 1, ++ap.id, ap.tx_op, rem > chunk ? WPS_FLAG_MORE : 0, first, (uint16_t)ap.tx_n, ap.tx + ap.tx_off, chunk);
    ap.tx_off += chunk;
    send_eapol(f, fl);
}
static void ap_send_msg(int op, const uint8_t *m, size_t n)
{
    memcpy(ap.tx, m, n); ap.tx_n = n; ap.tx_off = 0; ap.tx_op = op;
    ap_send_next_frag();
}
static void ap_send_eap_failure(void)
{
    uint8_t f[8] = {1, 0, 0, 4, 4, (uint8_t)++ap.id, 0, 4};
    send_eapol(f, 8);
}

static void ap_rx_eapol(const uint8_t *e, int n)
{
    uint8_t out[WPS_MAX_MSG];
    ap.frames_rx++;
    if (n < 4) return;
    if (e[1] == 1) {                                             /* EAPOL-Start -> Identity request */
        ap.starts++;
        uint8_t f[64]; int fl = wps_eap_build_identity(f, sizeof f, 1, ++ap.id, "");
        send_eapol(f, fl);
        return;
    }
    if (e[1] != 0 || n < 9 || e[4] != 2) return;                 /* not an EAP Response */
    if (e[8] == 1) {                                             /* Identity response -> WSC_Start */
        ap_send_msg(WPS_OP_START, NULL, 0);
        return;
    }
    if (e[8] != 254 || n < 18) return;
    int op = e[16]; uint8_t fl = e[17]; const uint8_t *d = e + 18; size_t dl = (size_t)(e[6] << 8 | e[7]) - 14;
    if (op == WPS_OP_FRAG_ACK) { if (ap.tx_off < ap.tx_n) ap_send_next_frag(); return; }
    if (fl & WPS_FLAG_LEN) { d += 2; dl -= 2; ap.rx_have = 0; }
    if (ap.rx_have + dl > sizeof ap.rx) return;
    memcpy(ap.rx + ap.rx_have, d, dl); ap.rx_have += dl; ap.rx_op = op;
    if (fl & WPS_FLAG_MORE) {
        uint8_t f[64]; int fn = wps_eap_build(f, sizeof f, 1, ++ap.id, WPS_OP_FRAG_ACK, 0, 0, 0, NULL, 0);
        send_eapol(f, fn);
        return;
    }
    size_t mn = ap.rx_have; ap.rx_have = 0;
    if (op == WPS_OP_DONE) ap.done_seen = 1;
    int on = reg_rx(ap.reg, ap.rx, mn, out, sizeof out);
    if (on > 0) {
        uint8_t t = 0; wps_tlv_get8(out, (size_t)on, WPS_ATTR_MSG_TYPE, &t);
        ap_send_msg(t == WPS_MSG_NACK ? WPS_OP_NACK : WPS_OP_MSG, out, (size_t)on);
    } else if (op == WPS_OP_DONE || op == WPS_OP_NACK) ap_send_eap_failure();
}

static int io_tx(void *ud, const uint8_t *f, int n, int is_data)
{
    (void)ud;
    int type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    if (n < 24) return 0;
    if (type == 0) {
        memcpy(ap.sta, f + 10, 6);
        if (sub == 4) { ap.probes++; ap_probe_resp(); }
        else if (sub == 11) { ap.auths++; uint8_t b[6] = {0, 0, 2, 0, 0, 0}; send_mgmt(0xB0, b, 6); }
        else if (sub == 0) {
            ap.assocs++;
            const uint8_t *ies = f + 28; int il = n - 28;
            ap.assoc_rsn = find_ie(ies, il, 48) != NULL;
            for (const uint8_t *p = ies; p + 2 <= ies + il && p + 2 + p[1] <= ies + il; p += 2 + p[1])
                if (p[0] == 0xDD && p[1] >= 4 && !memcmp(p + 2, "\x00\x50\xF2\x04", 4)) ap.assoc_wsc = 1;
            uint8_t b[6] = {0x11, 0x04, 0, 0, 1, 0xC0};
            send_mgmt(0x10, b, 6);
        } else if (sub == 12) ap.deauths++;
        return 0;
    }
    if (type == 2 && is_data && !(f[1] & 0x40) && n > 32 && !memcmp(f + 24, LLC_EAPOL, 8)) ap_rx_eapol(f + 32, n - 32);
    return 0;
}

static int io_poll(void *ud, rtl_frame_cb cb, void *cbud, int ms)
{
    (void)ud; (void)ms;
    int cnt = 0;
    while (ap.qh != ap.qt) {
        uint8_t buf[704]; qf_t *e = &ap.q[ap.qh % QN];
        memcpy(buf, e->d, e->n); memset(buf + e->n, 0, 4);
        rtl_frame_t f = { .data = buf, .len = e->n + 4, .has_fcs = 1, .rssi_valid = 1, .rssi_dbm = -40, .rate = 4, .channel = 6 };
        ap.qh++;
        cb(cbud, &f);
        cnt++;
    }
    if (!cnt) usleep(300);
    return cnt;
}
static const sta_io_t IO = { io_tx, io_poll, NULL };

static void ap_reset(const char *reg_pin, int locked, int sel, int pwid, size_t frag)
{
    memset(&ap, 0, sizeof ap);
    memcpy(ap.bssid, "\x02\xaa\xbb\xcc\xdd\x01", 6);
    ap.locked = locked; ap.sel = sel; ap.pwid = pwid; ap.frag = frag;
    reg_init(&REG, reg_pin);
    ap.reg = &REG;
}

static rtl_t R0;
static wpsrun_res_t RES;

static int run(const char *pin)
{
    wpsrun_cfg_t cfg = { .ssid = "LoopNet", .channel = 6, .pin = pin, .msg_timeout_ms = 3000, .session_ms = 20000 };
    memcpy(cfg.bssid, ap.bssid, 6);
    int rc = wpsrun(&R0, &cfg, &RES);
    if (rc) printf("  result: fail step=%s reason=%s\n", RES.step, RES.reason);
    else printf("  result: ok\n");
    return rc;
}

static void check_cred(void)
{
    CHECK(RES.ok);
    CHECK(RES.cred.ssid_len == strlen(REG.ssid) && !memcmp(RES.cred.ssid, REG.ssid, RES.cred.ssid_len));
    CHECK(!strcmp((char *)RES.cred.key, REG.key));
    char sec[16], key[130]; const char *why;
    CHECK(wpsrun_cred_profile(&RES.cred, sec, sizeof sec, key, sizeof key, &why) == 0 && !strcmp(sec, "wpa2") && !strcmp(key, REG.key));
    CHECK(ap.probes >= 1 && ap.auths >= 1 && ap.assocs == 1 && ap.assoc_wsc && !ap.assoc_rsn);
    CHECK(ap.starts >= 1 && ap.done_seen && REG.stage == 5 && ap.deauths == 1);
}

int main(void)
{
    srand(11);
    sta_io = &IO;
    char pin[9]; wps_pin_generate(1234567, pin);
    char wrong[9]; wps_pin_generate(7654321, wrong);

    printf("scenario: PIN %s (fragmented AP messages)\n", pin);
    ap_reset(pin, 0, 1, 0, 300);
    CHECK(run(pin) == 0); check_cred();

    printf("scenario: push button, button window open\n");
    ap_reset("00000000", 0, 1, WPS_DEVPW_PBC, 1398);
    CHECK(run(NULL) == 0); check_cred();

    printf("scenario: wrong PIN\n");
    ap_reset(wrong, 0, 1, 0, 1398);
    CHECK(run(pin) == -1 && RES.pin_wrong && !RES.ok && !strcmp(RES.step, "eap"));
    CHECK(REG.msg_len[WPS_MSG_M7] == 0 || REG.stage == -1);
    CHECK(ap.deauths == 1);

    printf("scenario: AP setup locked (nothing is transmitted beyond the probe)\n");
    ap_reset(pin, 1, 1, 0, 1398);
    CHECK(run(pin) == -1 && RES.locked && !strcmp(RES.reason, "ap_setup_locked"));
    CHECK(ap.auths == 0 && ap.assocs == 0);

    printf("scenario: PBC but no button window\n");
    ap_reset("00000000", 0, 0, 0, 1398);
    CHECK(run(NULL) == -1 && !strcmp(RES.reason, "pbc_inactive"));
    CHECK(ap.auths == 0 && ap.assocs == 0);

    printf("scenario: registrar not ready (M2D)\n");
    ap_reset(pin, 0, 1, 0, 1398);
    REG.m2d = 1;
    CHECK(run(pin) == -1 && RES.not_ready && !strcmp(RES.step, "m2d"));

    printf("scenario: PIN of the wrong length is refused before association\n");
    ap_reset(pin, 0, 1, 0, 1398);
    CHECK(run("123") == -1 && !strcmp(RES.step, "eap") && !strcmp(RES.reason, "bad_pin"));
    CHECK(ap.auths == 0);

    printf("scenario: credential -> profile mapping\n");
    {
        wps_cred_t c; char sec[16], key[130]; const char *why;
        memset(&c, 0, sizeof c); memcpy(c.ssid, "n", 1); c.ssid_len = 1;
        c.auth_type = WPS_AUTH_OPEN; c.encr_type = WPS_ENCR_NONE;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == 0 && !strcmp(sec, "open") && !key[0]);
        c.auth_type = 0x0022; c.encr_type = 0x000C; strcpy((char *)c.key, "passphrase1"); c.key_len = 11;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == 0 && !strcmp(sec, "wpa2") && !strcmp(key, "passphrase1"));
        c.auth_type = WPS_AUTH_WPAPSK; c.encr_type = WPS_ENCR_TKIP;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == 0 && !strcmp(sec, "wpa"));
        c.auth_type = WPS_AUTH_OPEN; c.encr_type = WPS_ENCR_WEP; strcpy((char *)c.key, "abcde"); c.key_len = 5;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == 0 && !strcmp(sec, "wep") && !strcmp(key, "abcde"));
        c.auth_type = WPS_AUTH_WPA2; c.encr_type = WPS_ENCR_AES;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == -1);
        c.auth_type = WPS_AUTH_WPA2PSK; c.key_is_hex_psk = 1; c.key_len = 64;
        CHECK(wpsrun_cred_profile(&c, sec, sizeof sec, key, sizeof key, &why) == -1);
    }
    printf("test_link_wps (software loopback, not an air test): %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
