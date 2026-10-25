// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// wpslink: one WPS enrollee registration. See wpslink.h and docs/WPS.md.
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "wpslink.h"
#include "sta.h"

#define OUT(...) do { if (cfg->out) { fprintf(cfg->out, "wps: " __VA_ARGS__); fputc('\n', cfg->out); fflush(cfg->out); } } while (0)

static long mono_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

typedef struct {
    sta_t *s; wps_eap_t *eap; const wpsrun_cfg_t *cfg;
    long last_rx; int frames, eap_err;
} ctx_t;

static void send_eapol(ctx_t *c, const uint8_t *e, int n)
{
    static const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    uint8_t body[8 + WPS_EAP_MAX_FRAME];
    memcpy(body, llc, 8); memcpy(body + 8, e, (size_t)n);
    sta_send_data(c->s, c->s->bssid, body, 8 + n, 0, 60);
}

// A data frame for us: unprotected, LLC/SNAP 0x888E -> the EAP-WSC engine; every reply goes out at once.
static void on_data(void *ud, const uint8_t *d, int len, const rtl_frame_t *f)
{
    ctx_t *c = ud;
    (void)f;
    int sub = d[0] >> 4, qos = (sub & 8) != 0, ht = (d[1] & 0x80) != 0;
    int hl = 24 + (qos ? 2 : 0) + (ht ? 4 : 0);
    if (len < hl + 8 + 4 || (d[1] & 0x40)) return;
    if (memcmp(d + hl, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) return;
    const uint8_t *e = d + hl + 8; int el = len - hl - 8;
    int want = 4 + (e[2] << 8 | e[3]);
    if (want < el) el = want;
    c->last_rx = mono_ms(); c->frames++;
    uint8_t out[WPS_EAP_MAX_FRAME];
    int n = wps_eap_rx(c->eap, e, (size_t)el, out, sizeof out);
    if (n > 0) send_eapol(c, out, n);
    else if (n < 0) c->eap_err++;
}

static int fail(wpsrun_res_t *res, const char *step, const char *reason)
{
    res->ok = 0;
    snprintf(res->step, sizeof res->step, "%s", step);
    snprintf(res->reason, sizeof res->reason, "%s", reason);
    return -1;
}

static const char *fail_text(wps_fail_t f)
{
    switch (f) {
    case WPS_FAIL_BAD_MSG: return "bad_message";
    case WPS_FAIL_AUTHENTICATOR: return "authenticator_mismatch";
    case WPS_FAIL_DECRYPT: return "decrypt_failed";
    case WPS_FAIL_PIN_AUTH: return "pin_wrong";
    case WPS_FAIL_PWID_MISMATCH: return "device_password_id_mismatch";
    case WPS_FAIL_AP_NACK: return "ap_nack";
    case WPS_FAIL_BAD_KEY: return "bad_dh_key";
    case WPS_FAIL_EAP_FAILURE: return "eap_failure";
    case WPS_FAIL_BAD_CRED: return "bad_credential";
    default: return "failed";
    }
}

int wpsrun(rtl_t *r, const wpsrun_cfg_t *cfg, wpsrun_res_t *res)
{
    memset(res, 0, sizeof *res);
    int msg_to = cfg->msg_timeout_ms ? cfg->msg_timeout_ms : 10000, sess_to = cfg->session_ms ? cfg->session_ms : 120000;
    sta_t s;
    sta_init(&s, r, cfg->ssid, cfg->bssid, cfg->channel);
    if (cfg->channel && (!r || r->channel != cfg->channel || sta_io) && sta_set_channel(&s, cfg->channel)) return fail(res, "scan", "set_channel_failed");
    OUT("sa=%02x:%02x:%02x:%02x:%02x:%02x channel=%d", s.mac[0], s.mac[1], s.mac[2], s.mac[3], s.mac[4], s.mac[5], cfg->channel);
    if (sta_scan(&s, 4000)) return fail(res, "scan", "no_probe_response");

    wps_ap_info_t ap; memset(&ap, 0, sizeof ap); memcpy(ap.bssid, s.bssid, 6);
    if (wps_ap_parse(s.ies, (size_t)s.ies_len, &ap) == 1) {      // fresh look at the AP's own Probe Response
        wps_ap_reason_t why = wps_ap_check(&ap, cfg->pin ? WPS_MODE_PIN : WPS_MODE_PBC);
        if (why != WPS_AP_OK) { res->locked = why == WPS_AP_LOCKED; return fail(res, "scan", why == WPS_AP_LOCKED ? "ap_setup_locked" : why == WPS_AP_PBC_INACTIVE ? "pbc_inactive" : "ap_not_ready"); }
    } else OUT("no WSC element seen in the Probe Response (truncated?); trying anyway");

    wps_cfg_t wc; memset(&wc, 0, sizeof wc);
    memcpy(wc.mac, s.mac, 6); wps_uuid_from_mac(s.mac, wc.uuid); wc.pin = cfg->pin;
    wps_eap_t *eap = calloc(1, sizeof *eap);
    if (!eap) return fail(res, "eap", "out_of_memory");
    int rc = -1;
    if (wps_eap_init(eap, &wc)) { free(eap); return fail(res, "eap", "bad_pin"); }

    s.auth_algo = 0;
    s.sec_ie_len = wps_build_assoc_req_ie(s.sec_ie, sizeof s.sec_ie);      // WSC IE, and NO RSN IE: registration runs unencrypted
    if (s.sec_ie_len <= 0) { s.sec_ie_len = 0; wps_eap_clear(eap); free(eap); return fail(res, "assoc", "ie_build_failed"); }
    if (sta_auth(&s)) { char b[40]; snprintf(b, sizeof b, "status=%d", s.last_status); wps_eap_clear(eap); free(eap); return fail(res, "auth", b); }
    if (sta_assoc(&s)) { char b[40]; snprintf(b, sizeof b, "status=%d", s.last_status); wps_eap_clear(eap); free(eap); return fail(res, "assoc", b); }
    OUT("associated (open) aid=%d, starting EAP-WSC (%s)", s.aid, cfg->pin ? "PIN" : "push button");

    ctx_t c = { .s = &s, .eap = eap, .cfg = cfg, .last_rx = mono_ms() };
    s.def_cb = on_data; s.def_ud = &c;
    long t0 = mono_ms(), last_start = 0; int starts = 0;
    char reason[160] = "";
    for (;;) {
        long now = mono_ms();
        int done = wps_eap_result(eap);
        if (done) break;
        if (eap->en.state == WPS_ST_M2D) { res->not_ready = 1; snprintf(reason, sizeof reason, "registrar_not_ready (no button window open / PIN not entered on the AP)"); break; }
        if (cfg->stop && *cfg->stop) { snprintf(reason, sizeof reason, "interrupted"); break; }
        if (s.deauth_seen || s.disassoc_seen) { snprintf(reason, sizeof reason, "ap_%s reason=%d", s.deauth_seen ? "deauth" : "disassoc", s.deauth_seen ? s.deauth_reason : s.disassoc_reason); break; }
        if (now - t0 > sess_to) { snprintf(reason, sizeof reason, "session_timeout"); break; }
        if (now - c.last_rx > msg_to && c.frames) { snprintf(reason, sizeof reason, "message_timeout after %d frames", c.frames); break; }
        if (!c.frames && now - last_start >= 3000) {         // no identity request yet: (re)send the EAPOL-Start
            if (starts >= 3) { snprintf(reason, sizeof reason, "no_eap_start_from_ap"); break; }
            uint8_t st[4]; int n = wps_eap_start_frame(st, sizeof st);
            send_eapol(&c, st, n); starts++; last_start = now; c.last_rx = now;
        }
        sta_poll(&s, 50, NULL, NULL);
        if (cfg->idle) cfg->idle(cfg->idle_ud);
    }
    int result = wps_eap_result(eap);
    if (result == 1) {
        if (s.deauth_seen == 0) sta_poll(&s, 100, NULL, NULL);                 // let our WSC_Done go out
        res->ok = 1; res->cred = eap->en.cred; rc = 0;
        OUT("credential received for ssid_len=%zu", res->cred.ssid_len);
    } else {
        res->fail = eap->en.fail; res->cfg_error = eap->en.cfg_error;
        if (result < 0) {
            res->pin_wrong = eap->en.fail == WPS_FAIL_PIN_AUTH || (eap->en.fail == WPS_FAIL_AP_NACK && eap->en.cfg_error == WPS_CFG_PIN_AUTH_FAILURE);
            res->locked = eap->en.fail == WPS_FAIL_AP_NACK && eap->en.cfg_error == WPS_CFG_SETUP_LOCKED;
            snprintf(reason, sizeof reason, "%s cfg_error=%u", res->pin_wrong ? "pin_wrong" : res->locked ? "ap_setup_locked" : fail_text(eap->en.fail), eap->en.cfg_error);
        }
        fail(res, res->not_ready ? "m2d" : "eap", reason[0] ? reason : "failed");
    }
    if (s.associated && !s.deauth_seen) sta_deauth(&s, 3);
    wps_eap_clear(eap);
    free(eap);
    return rc;
}

int wpsrun_cred_profile(const wps_cred_t *c, char *sec, size_t secn, char *key, size_t keyn, const char **why)
{
    *why = "";
    if (c->ssid_len == 0 || c->ssid_len > 32) { *why = "bad_ssid"; return -1; }
    if (c->auth_type & (WPS_AUTH_WPA | WPS_AUTH_WPA2)) { *why = "802.1X_credential_not_supported"; return -1; }
    if (c->encr_type == WPS_ENCR_NONE && (c->auth_type == WPS_AUTH_OPEN)) { snprintf(sec, secn, "open"); key[0] = 0; return 0; }
    if (c->encr_type & WPS_ENCR_WEP) {
        if (!c->key_len || c->key_len >= keyn) { *why = "bad_wep_key"; return -1; }
        snprintf(sec, secn, "wep"); snprintf(key, keyn, "%s", (const char *)c->key); return 0;
    }
    if (c->auth_type & (WPS_AUTH_WPA2PSK | WPS_AUTH_WPAPSK)) {
        if (c->key_is_hex_psk) { *why = "raw_64_hex_psk_not_supported"; return -1; }
        if (c->key_len < 8 || c->key_len > 63) { *why = "bad_passphrase_length"; return -1; }
        snprintf(sec, secn, "%s", (c->auth_type & WPS_AUTH_WPA2PSK) ? "wpa2" : "wpa");
        snprintf(key, keyn, "%s", (const char *)c->key);
        return 0;
    }
    *why = "unsupported_auth_type";
    return -1;
}
