// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// awusd: the adapter daemon. One single-threaded event loop owns the USB device and a unix control socket (see proto.h).
//   States: NO_DEVICE, IDLE, SCANNING, JOINING, CONNECTED, RF_OFF (derived from what the daemon is doing, never stored).
//   Jobs: bring the chip up when it appears (poll every second, so unplug/replug works), auto-join the best visible saved
//   profile, reconnect with backoff (1,2,4,8,16,30 s) when the link drops, re-initialise after sleep, renew DHCP at T1/T2
//   (net.c), drive the LED (led.c), enforce the country table (country.c) on scan and join.
//   As root it also opens a utun like `wifi --tun` (host route to the gateway only; a default route only if the profile
//   says default_route=true). Unprivileged it is link-only: associated, DHCP lease, gateway ping, no packets to macOS.
// Long jobs (scan, join) keep answering the socket through the rtl_rx_idle hook: status is answered at once; leave, rf off,
// debug drop... abort the job and run when it has unwound; anything else gets "ERR busy_...".
// Keys travel over the 0600 socket and are never logged and never put on a command line.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "bringup.h"
#include "link.h"
#include "tun.h"
#include "scanlib.h"
#include "country.h"
#include "profile.h"
#include "proto.h"
#include "led.h"

#define now_ms link_now_ms
#define LOSS_SILENCE_MS 6000      // nothing heard from the AP for this long = link lost
#define WAKE_JUMP_MS 3000         // monotonic-vs-uptime clock divergence that means "the machine slept"
#define REG_RF_CTRL 0x001F

typedef enum { B_NONE, B_SCAN, B_JOIN, B_OTHER } busy_t;
typedef enum { ST_NO_DEVICE, ST_IDLE, ST_SCANNING, ST_JOINING, ST_CONNECTED, ST_RF_OFF } state_t;
static const char *const state_name[] = { "NO_DEVICE", "IDLE", "SCANNING", "JOINING", "CONNECTED", "RF_OFF" };

typedef struct {                  // a connection we want (and remember for reconnects)
    char ssid[33], key[130];
    link_sec_t sec;
    int hidden, channel, have_bssid, default_route;
    uint8_t bssid[6];
} conn_t;

static struct {
    // device
    rtl_t r; int dev; long next_open, sim_unplug_until, last_live;
    // link
    link_t L; int linked; conn_t cur;                // cur = the connection that is up
    conn_t target; int have_target;                  // what to reconnect to
    int hold;                                        // manual leave: no auto join until join / autojoin on / profile add auto=1
    int rf_off, autojoin_on;
    int attempt; long next_try; char skip_ssid[33];
    long t_connected; char last_error[160];
    // work in progress
    busy_t busy; int bg; volatile sig_atomic_t abort_op, stop_req;
    int in_hook;
    // settings
    char country[3]; int txpower_pinned, txpower;
    profiles_t profiles; char profiles_path[512], conf_path[560];
    scan_t scan; int have_scan; long scan_at;
    led_t led; int led_force;                        // -1 = automatic, 0 / 1 = held by `debug led`
    // tun (root only)
    int tun_fd; char tun_name[16], tun_ip[20], tun_gw[20], tun_mask[20]; int tun_default;
    // counters
    long t_start; unsigned long connects, reconnects, drops, wakes, replugs, scans, joins_failed;
    int had_dev;
    // socket
    int lfd; char sock[256]; uid_t sock_uid;
    long gap0; int gap_init;
    FILE *logf;
    unsigned long last_dec_ok, last_tun;
} D;

static void LOGF(const char *fmt, ...)
{
    if (!D.logf) return;
    va_list ap; va_start(ap, fmt);
    fprintf(D.logf, "[%8ld] ", now_ms() - D.t_start);
    vfprintf(D.logf, fmt, ap);
    fputc('\n', D.logf);
    va_end(ap);
    fflush(D.logf);
}

static void set_err(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vsnprintf(D.last_error, sizeof D.last_error, fmt, ap);
    va_end(ap);
}

static state_t cur_state(void)
{
    if (!D.dev) return ST_NO_DEVICE;
    if (D.rf_off) return ST_RF_OFF;
    if (D.busy == B_SCAN) return ST_SCANNING;
    if (D.busy == B_JOIN) return ST_JOINING;
    return D.linked ? ST_CONNECTED : ST_IDLE;
}

// ---------------------------------------------------------------- settings file (country, tx power)
static void conf_save(void)
{
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.tmp", D.conf_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fchmod(fileno(f), 0600);
    fprintf(f, "country=%s\n", D.country);
    if (D.txpower_pinned) fprintf(f, "txpower=%d\n", D.txpower);
    fflush(f); fsync(fileno(f)); fclose(f);
    rename(tmp, D.conf_path);
}

static void conf_load(void)
{
    FILE *f = fopen(D.conf_path, "r");
    if (!f) return;
    char l[80];
    while (fgets(l, sizeof l, f)) {
        char cc[3];
        int v;
        if (sscanf(l, "country=%2s", cc) == 1 && !country_norm(cc, D.country)) continue;
        if (sscanf(l, "txpower=%d", &v) == 1 && v >= 0 && v <= 63) { D.txpower_pinned = 1; D.txpower = v; }
    }
    fclose(f);
}

// ---------------------------------------------------------------- tun (root only)
static int is_root(void) { return geteuid() == 0; }

static void tun_close(void)
{
    if (D.tun_fd < 0) return;
    if (D.tun_default) tun_del_default_split(D.tun_name);
    close(D.tun_fd);                              // closing the utun removes its routes
    LOGF("tun %s closed", D.tun_name);
    D.tun_fd = -1; D.tun_default = 0; D.tun_name[0] = 0;
    D.L.tun_fd = -1;
}

// Make the utun match the current lease. Returns 0 (or link-only when unprivileged), -1 on error (logged).
static int tun_sync(void)
{
    if (!is_root()) return 0;
    net_lease_t *ls = &D.L.n.lease;
    char ip[20], gw[20], mask[20];
    link_ipstr(ip, sizeof ip, ls->ip); link_ipstr(gw, sizeof gw, ls->gw); link_ipstr(mask, sizeof mask, ls->mask);
    if (D.tun_fd < 0) {
        D.tun_fd = tun_open(D.tun_name);
        if (D.tun_fd < 0) { LOGF("tun_open failed: %s", strerror(errno)); set_err("tun_open: %s", strerror(errno)); return -1; }
        D.tun_ip[0] = 0;
    }
    if (strcmp(ip, D.tun_ip) || strcmp(gw, D.tun_gw) || strcmp(mask, D.tun_mask)) {
        if (D.tun_default) { tun_del_default_split(D.tun_name); D.tun_default = 0; }
        if (tun_configure(D.tun_name, ip, gw, mask)) { LOGF("tun_configure failed"); set_err("tun_configure failed"); return -1; }
        snprintf(D.tun_ip, sizeof D.tun_ip, "%s", ip); snprintf(D.tun_gw, sizeof D.tun_gw, "%s", gw); snprintf(D.tun_mask, sizeof D.tun_mask, "%s", mask);
        LOGF("tun %s up ip=%s gw=%s", D.tun_name, ip, gw);
    }
    if (D.cur.default_route && !D.tun_default) {
        if (tun_add_default_split(D.tun_name) == 0) { D.tun_default = 1; LOGF("default route via %s (two /1 routes)", D.tun_name); }
        else LOGF("default route add failed");
    } else if (!D.cur.default_route && D.tun_default) { tun_del_default_split(D.tun_name); D.tun_default = 0; }
    D.L.tun_fd = D.tun_fd;
    return 0;
}

// ---------------------------------------------------------------- device
static void led_apply(void);

static void dev_close(const char *why)
{
    LOGF("device closed: %s", why);
    D.linked = 0;
    tun_close();
    if (D.dev) rtl_close(&D.r);
    D.dev = 0;
    D.r.h = NULL; D.r.ctx = NULL;
    D.busy = B_NONE;
}

static int rf_disable(void) { return rtl_w8(&D.r, REG_RF_CTRL, 0x00); }

static void dev_try_open(void)
{
    if (now_ms() < D.sim_unplug_until) return;
    char b[160]; const char *step = "";
    memset(&D.r, 0, sizeof D.r);
    D.r.tx_power_pinned = D.txpower_pinned; D.r.tx_power = D.txpower;
    if (rtl_bringup(&D.r, 1, &step, b, sizeof b)) {
        if (strcmp(step, "open")) { LOGF("bring-up failed at %s: %s", step, b); set_err("bringup %s: %s", step, b); }
        rtl_close(&D.r);
        return;
    }
    if (rtl_set_monitor(&D.r)) { LOGF("set_monitor failed"); rtl_close(&D.r); set_err("set_monitor failed"); return; }
    if (D.txpower_pinned) rtl_pin_tx_power(&D.r, (uint8_t)D.txpower);
    D.dev = 1;
    if (D.had_dev) D.replugs++;
    D.had_dev = 1;
    led_init(&D.led); D.led_force = -1;
    LOGF("device up (cut %d), country %s, tx power %d", D.r.cut, D.country, D.r.tx_power);
    if (D.rf_off) { rf_disable(); LOGF("rf stays off"); }
    D.last_live = now_ms();
    if (!D.hold && !D.rf_off && D.have_target) { D.attempt = 0; D.next_try = now_ms() + 500; }
    led_apply();
}

static void link_drop(int polite)
{
    if (D.linked && polite) link_leave(&D.L);
    D.linked = 0;
}

// ---------------------------------------------------------------- LED
static led_mode_t want_led(void)
{
    switch (cur_state()) {
    case ST_CONNECTED: return LED_SOLID;
    case ST_SCANNING: case ST_JOINING: return LED_FAST;
    case ST_RF_OFF: case ST_NO_DEVICE: return LED_OFF;
    default: return LED_SLOW;
    }
}

static void led_apply(void)
{
    if (!D.dev || rtl_usb_dead || D.led_force >= 0) return;
    led_set_mode(&D.led, want_led(), now_ms());
    led_tick(&D.led, &D.r, now_ms());
}

// ---------------------------------------------------------------- protocol output helpers
static void kv(FILE *o, const char *k, const char *fmt, ...)
{
    char v[400], e[1300];
    va_list ap; va_start(ap, fmt);
    vsnprintf(v, sizeof v, fmt, ap);
    va_end(ap);
    proto_enc(e, sizeof e, v);
    fprintf(o, "%s=%s\n", k, e);
}
static void err(FILE *o, const char *fmt, ...)
{
    char v[300];
    va_list ap; va_start(ap, fmt);
    vsnprintf(v, sizeof v, fmt, ap);
    va_end(ap);
    fprintf(o, "ERR %s\n", v);
}

static link_sec_t parse_sec(const char *v, int *ok)
{
    *ok = 1;
    if (!v || !strcmp(v, "auto")) return LINK_SEC_AUTO;
    if (!strcmp(v, "open")) return LINK_SEC_OPEN;
    if (!strcmp(v, "wep")) return LINK_SEC_WEP;
    if (!strcmp(v, "wep-shared")) return LINK_SEC_WEP_SHARED;
    if (!strcmp(v, "wpa")) return LINK_SEC_WPA;
    if (!strcmp(v, "wpa2")) return LINK_SEC_WPA2;
    *ok = 0;
    return LINK_SEC_AUTO;
}

static int parse_bssid(const char *s, uint8_t *b)
{
    unsigned x[6]; char t;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &t) != 6) return -1;
    for (int i = 0; i < 6; i++) { if (x[i] > 255) return -1; b[i] = (uint8_t)x[i]; }
    return 0;
}

static int flag(const char *v, int dflt) { return !v ? dflt : (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes") || !strcmp(v, "on")); }

// ---------------------------------------------------------------- scan helpers
static int do_scan(int band, int dwell, int passes)
{
    D.busy = B_SCAN;
    led_apply();
    scan_reset(&D.scan, D.country);
    D.abort_op = 0;
    int rc = scan_run(&D.r, &D.scan, band, dwell, passes, &D.abort_op);
    D.busy = B_NONE;
    if (rc == 0) { scan_sort(&D.scan); D.have_scan = 1; D.scan_at = now_ms(); D.scans++; }
    led_apply();
    return rc;
}

// Best allowed entry with this SSID in the last scan, or NULL. *blocked = a match exists only on blocked channels.
static const scan_entry_t *scan_find(const char *ssid, int *blocked)
{
    const scan_entry_t *best = NULL;
    if (blocked) *blocked = 0;
    for (int i = 0; i < D.scan.n; i++) {
        const scan_entry_t *e = &D.scan.aps[i];
        if (scan_is_hidden(&e->ap) || (size_t)e->ap.ssid_len != strlen(ssid) || memcmp(e->ap.ssid, ssid, e->ap.ssid_len)) continue;
        if (!e->allowed) { if (blocked) *blocked = 1; continue; }
        if (!best || scan_rssi(e) > scan_rssi(best)) best = e;
    }
    return best;
}

// ---------------------------------------------------------------- join
// Joins c (blocking; the hook keeps the socket alive). 0 = connected, else -1 with a reason in why.
static int do_join(const conn_t *c, char *why, size_t wn)
{
    conn_t cc = *c;
    if (!D.dev) { snprintf(why, wn, "no_device"); return -1; }
    if (D.rf_off) { snprintf(why, wn, "rf_off"); return -1; }
    if (D.linked) { link_drop(1); }
    D.abort_op = 0;
    int blocked = 0;
    if (cc.channel && country_chan(D.country, cc.channel) == CC_BLOCKED) {
        snprintf(why, wn, "channel_blocked_by_country %s ch %d", D.country, cc.channel);
        return -1;
    }
    if (!cc.channel && !cc.hidden) {
        int rc = do_scan(0, 160, 2);
        if (rc == 1) { snprintf(why, wn, "interrupted"); return -1; }
        if (rc < 0) { snprintf(why, wn, "usb_error"); return -1; }
        const scan_entry_t *e = scan_find(cc.ssid, &blocked);
        if (!e) { snprintf(why, wn, blocked ? "channel_blocked_by_country %s" : "ssid_not_found", D.country); return -1; }
        cc.channel = e->channel; memcpy(cc.bssid, e->bssid, 6); cc.have_bssid = 1;
    }
    D.busy = B_JOIN;
    led_apply();
    D.abort_op = 0;
    link_init(&D.L, &D.r);
    D.L.out = D.logf; D.L.stop = &D.abort_op;
    link_cfg_t cfg = { .ssid = cc.ssid, .bssid = cc.have_bssid ? cc.bssid : NULL, .channel = cc.channel, .hidden = cc.hidden,
                       .sec = cc.sec, .key = cc.key[0] ? cc.key : NULL };
    int rc = link_join(&D.r, &cfg, &D.L);
    D.busy = B_NONE;
    if (rc) {
        snprintf(why, wn, "%s:%s", D.L.fail_step, D.L.fail_reason);
        D.joins_failed++;
        led_apply();
        return -1;
    }
    if (country_chan(D.country, D.L.s.channel) == CC_BLOCKED) {      // hidden SSID found by link's own scan
        link_leave(&D.L);
        snprintf(why, wn, "channel_blocked_by_country %s ch %d", D.country, D.L.s.channel);
        led_apply();
        return -1;
    }
    D.linked = 1;
    D.cur = cc;
    D.target = cc; D.have_target = 1;
    D.t_connected = now_ms();
    D.L.s.last_rx_ms = now_ms();
    D.last_dec_ok = D.L.st_dec_ok;
    D.connects++;
    if (D.tun_fd >= 0 || is_root()) tun_sync();
    D.hold = 0; D.attempt = 0; D.skip_ssid[0] = 0;
    LOGF("connected ssid=%s ch=%d", cc.ssid, D.L.s.channel);
    led_apply();
    return 0;
}

static void link_lost(const char *why)
{
    LOGF("link lost: %s", why);
    D.drops++;
    link_drop(0);
    D.attempt = 0;
    D.next_try = now_ms() + backoff_ms(0);
    set_err("link lost: %s", why);
    led_apply();
}

static void do_leave(void)
{
    link_drop(1);
    D.have_target = 0;
    D.hold = 1;
    tun_close();
    LOGF("left (manual); auto-join held");
    led_apply();
}

// ---------------------------------------------------------------- wake / unplug
static void on_wake(const char *how)
{
    D.wakes++;
    LOGF("wake (%s): full re-initialisation", how);
    if (D.dev) dev_close("wake");
    D.next_open = now_ms() + 500;
}

static long uptime_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_UPTIME_RAW, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void wake_check(void)
{
    long gap = now_ms() - uptime_ms();       // grows by the time spent asleep
    if (D.gap_init && gap - D.gap0 > WAKE_JUMP_MS) on_wake("clock jump");
    D.gap0 = gap; D.gap_init = 1;
}

// ---------------------------------------------------------------- status
static void cmd_status(FILE *o)
{
    state_t st = cur_state();
    long now = now_ms();
    fprintf(o, "OK\n");
    kv(o, "state", "%s", state_name[st]);
    kv(o, "device", "%s", D.dev ? "present" : "absent");
    kv(o, "rf", "%s", D.rf_off ? "off" : "on");
    kv(o, "country", "%s", D.country);
    kv(o, "uptime_s", "%ld", (now - D.t_start) / 1000);
    kv(o, "root", "%d", is_root());
    kv(o, "hold", "%d", D.hold);
    kv(o, "autojoin", "%d", D.autojoin_on);
    kv(o, "profiles", "%d", D.profiles.n);
    if (D.dev) {
        kv(o, "txpower", "%d", D.r.tx_power);
        kv(o, "txpower_pinned", "%d", D.r.tx_power_pinned);
        kv(o, "channel", "%d", D.r.channel);
        uint32_t c20 = rtl_r32(&D.r, 0xC20);
        kv(o, "txpower_reg_c20", "0x%08x", c20);
        kv(o, "rf_ctrl_reg", "0x%02x", rtl_r8(&D.r, REG_RF_CTRL));
        uint8_t lc; uint32_t gp; int lit;
        led_readback(&D.r, &lc, &gp, &lit);
        static const char *const ln[] = { "off", "solid", "slow", "fast" };
        kv(o, "led_mode", "%s", D.led_force >= 0 ? "forced" : ln[D.led.mode]);
        kv(o, "led_reg_lit", "%d", lit);
        kv(o, "led_ledcfg2", "0x%02x", lc);
        kv(o, "led_gpio_pin_ctrl_2", "0x%08x", gp);
    }
    if (st == ST_CONNECTED) {
        char ip[20], gw[20], mk[20];
        link_ipstr(ip, sizeof ip, D.L.n.lease.ip); link_ipstr(gw, sizeof gw, D.L.n.lease.gw); link_ipstr(mk, sizeof mk, D.L.n.lease.mask);
        kv(o, "ssid", "%s", D.cur.ssid);
        kv(o, "bssid", "%02x:%02x:%02x:%02x:%02x:%02x", D.L.s.bssid[0], D.L.s.bssid[1], D.L.s.bssid[2], D.L.s.bssid[3], D.L.s.bssid[4], D.L.s.bssid[5]);
        kv(o, "link_channel", "%d", D.L.s.channel);
        kv(o, "security", "%s", link_sec_str(D.L.sec));
        kv(o, "pairwise", "%s", link_cipher_str(D.L.pw_cipher));
        kv(o, "rssi_dbm", "%d", D.L.s.rssi_avg);
        kv(o, "rx_rate_code", "%d", D.L.s.rx_rate);
        kv(o, "ip", "%s", ip); kv(o, "gateway", "%s", gw); kv(o, "netmask", "%s", mk);
        kv(o, "lease_s", "%u", D.L.n.lease.lease_s);
        kv(o, "lease_age_s", "%ld", (long)(((uint64_t)now - D.L.n.t_bound) / 1000));
        kv(o, "dhcp_renews", "%u", D.L.n.renews);
        kv(o, "dhcp_rebinds", "%u", D.L.n.rebinds);
        kv(o, "connected_s", "%ld", (now - D.t_connected) / 1000);
        kv(o, "tun", "%s", D.tun_fd >= 0 ? D.tun_name : (is_root() ? "none" : "link-only (not root)"));
        kv(o, "default_route", "%d", D.tun_default);
        kv(o, "rx_ap_frames", "%lu", D.L.s.rx_ap_frames);
    } else if (D.have_target && !D.hold && st == ST_IDLE) {
        kv(o, "reconnecting", "%s", D.target.ssid);
        kv(o, "reconnect_attempt", "%d", D.attempt);
        kv(o, "next_try_in_s", "%ld", D.next_try > now ? (D.next_try - now + 999) / 1000 : 0);
    }
    kv(o, "connects", "%lu", D.connects);
    kv(o, "drops", "%lu", D.drops);
    kv(o, "reconnects", "%lu", D.reconnects);
    kv(o, "wakes", "%lu", D.wakes);
    kv(o, "replugs", "%lu", D.replugs);
    kv(o, "scans", "%lu", D.scans);
    kv(o, "usb_errors", "%lu", rtl_usb_errors);
    if (D.last_error[0]) kv(o, "last_error", "%s", D.last_error);
}

// ---------------------------------------------------------------- scan command
static void print_rows(FILE *o)
{
    for (int i = 0; i < D.scan.n; i++) {
        scan_row_t w;
        scan_row(&D.scan.aps[i], &w);
        char s[400], sec[200], ci[120], ph[160];
        proto_enc(s, sizeof s, w.ssid); proto_enc(sec, sizeof sec, w.security); proto_enc(ci, sizeof ci, w.cipher); proto_enc(ph, sizeof ph, w.phy);
        fprintf(o, "ap ssid=%s hidden=%d bssid=%s ch=%d rssi=%d sec=%s cipher=%s phy=%s wps=%d ok=%d dfs=%d ht=%d vht=%d he=%d streams=%d rate=%g\n",
                s, w.hidden, w.bssid, w.channel, w.rssi, sec, ci, ph, w.wps, w.allowed, w.dfs, w.ht, w.vht, w.he, w.streams, w.max_rate);
    }
}

static void cmd_scan(FILE *o, const proto_req_t *q)
{
    int band = 0, dwell = 250, passes = 2;
    const char *v;
    if ((v = proto_opt(q, "band"))) { if (!strcmp(v, "2")) band = 2; else if (!strcmp(v, "5")) band = 5; else if (strcmp(v, "all")) { err(o, "band must be 2, 5 or all"); return; } }
    if ((v = proto_opt(q, "dwell"))) dwell = atoi(v);
    if ((v = proto_opt(q, "passes"))) passes = atoi(v);
    if (dwell < 20 || dwell > 5000 || passes < 1 || passes > 50) { err(o, "bad dwell (20-5000) or passes (1-50)"); return; }
    if (!D.dev) { err(o, "no_device"); return; }
    if (D.rf_off) { err(o, "rf_off"); return; }
    int cached = 0;
    if (D.linked) {
        // The radio is tied to the AP's channel while associated; hopping would drop the link. Serve the last scan.
        if (!D.have_scan) { err(o, "busy_connected (no earlier scan to show; leave first)"); return; }
        cached = 1;
    } else {
        int rc = do_scan(band, dwell, passes);
        if (rc == 1) { err(o, "interrupted"); return; }
        if (rc < 0) { err(o, "usb_error"); return; }
    }
    fprintf(o, "OK\n");
    kv(o, "cached", "%d", cached);
    kv(o, "age_s", "%ld", (now_ms() - D.scan_at) / 1000);
    kv(o, "country", "%s", D.country);
    kv(o, "count", "%d", D.scan.n);
    kv(o, "dropped", "%d", D.scan.dropped);
    print_rows(o);
}

// ---------------------------------------------------------------- profiles
static void profile_from_req(const proto_req_t *q, profile_t *p, int *auto_given)
{
    const char *v;
    memset(p, 0, sizeof *p);
    snprintf(p->security, sizeof p->security, "auto");
    p->autojoin = 1;
    if ((v = proto_opt(q, "ssid"))) snprintf(p->ssid, sizeof p->ssid, "%s", v);
    if ((v = proto_opt(q, "key"))) snprintf(p->key, sizeof p->key, "%s", v);
    if ((v = proto_opt(q, "security"))) snprintf(p->security, sizeof p->security, "%s", v);
    if ((v = proto_opt(q, "priority"))) p->priority = atoi(v);
    p->hidden = flag(proto_opt(q, "hidden"), 0);
    p->default_route = flag(proto_opt(q, "default_route"), 0);
    *auto_given = proto_opt(q, "autojoin") != NULL;
    p->autojoin = flag(proto_opt(q, "autojoin"), 1);
}

static void cmd_profile(FILE *o, const proto_req_t *q)
{
    const char *sub = proto_pos(q, 0);
    if (!sub) { err(o, "usage: profile add|list|remove"); return; }
    if (!strcmp(sub, "list")) {
        fprintf(o, "OK\n");
        for (int i = 0; i < D.profiles.n; i++) {
            const profile_t *p = &D.profiles.p[i];
            char s[200], sec[40];
            proto_enc(s, sizeof s, p->ssid); proto_enc(sec, sizeof sec, p->security);
            fprintf(o, "profile ssid=%s security=%s hidden=%d priority=%d autojoin=%d default_route=%d key=%s\n",
                    s, sec, p->hidden, p->priority, p->autojoin, p->default_route, p->key[0] ? "set" : "none");
        }
        return;
    }
    if (!strcmp(sub, "add")) {
        profile_t p; int ag;
        profile_from_req(q, &p, &ag);
        const char *why = "";
        int rc = profiles_put(&D.profiles, &p, &why);
        if (rc == -2) { err(o, "profile table full (%d)", PROFILE_MAX); return; }
        if (rc) { err(o, "invalid profile: %s", why); return; }
        if (profiles_save(D.profiles_path, &D.profiles)) { err(o, "saved in memory but writing %s failed", D.profiles_path); return; }
        if (p.autojoin) { D.hold = 0; D.autojoin_on = 1; D.attempt = 0; D.next_try = 0; }
        LOGF("profile saved: %s (autojoin=%d prio=%d)", p.ssid, p.autojoin, p.priority);
        fprintf(o, "OK\n");
        return;
    }
    if (!strcmp(sub, "remove")) {
        const char *s = proto_opt(q, "ssid");
        if (!s && proto_pos(q, 1)) s = proto_pos(q, 1);
        if (!s || profiles_remove(&D.profiles, s)) { err(o, "no such profile"); return; }
        profiles_save(D.profiles_path, &D.profiles);
        LOGF("profile removed: %s", s);
        fprintf(o, "OK\n");
        return;
    }
    err(o, "usage: profile add|list|remove");
}

// ---------------------------------------------------------------- join command
static void conn_from_profile(conn_t *c, const profile_t *p)
{
    int ok;
    memset(c, 0, sizeof *c);
    snprintf(c->ssid, sizeof c->ssid, "%s", p->ssid);
    snprintf(c->key, sizeof c->key, "%s", p->key);
    c->sec = parse_sec(p->security, &ok);
    c->hidden = p->hidden; c->default_route = p->default_route;
}

static void cmd_join(FILE *o, const proto_req_t *q)
{
    const char *v, *ssid = proto_opt(q, "ssid");
    if (!ssid || !*ssid) { err(o, "usage: join ssid=NAME [key=.. sec=.. hidden=0|1 bssid=.. ch=N default_route=0|1]"); return; }
    conn_t c;
    const profile_t *p = profiles_find(&D.profiles, ssid);
    if (p && !proto_opt(q, "key") && !proto_opt(q, "sec")) conn_from_profile(&c, p);
    else {
        memset(&c, 0, sizeof c);
        snprintf(c.ssid, sizeof c.ssid, "%s", ssid);
        int ok;
        c.sec = parse_sec(proto_opt(q, "sec"), &ok);
        if (!ok) { err(o, "sec must be auto, open, wep, wep-shared, wpa or wpa2"); return; }
        if ((v = proto_opt(q, "key"))) snprintf(c.key, sizeof c.key, "%s", v);
        if (c.sec == LINK_SEC_OPEN) c.key[0] = 0;
        if (c.sec >= LINK_SEC_WEP && !c.key[0]) { err(o, "sec %s needs key", link_sec_str(c.sec)); return; }
        c.hidden = flag(proto_opt(q, "hidden"), 0);
    }
    if ((v = proto_opt(q, "ch"))) { c.channel = atoi(v); if (c.channel < 0 || c.channel > 165) { err(o, "bad ch"); return; } }
    if ((v = proto_opt(q, "bssid"))) { if (parse_bssid(v, c.bssid)) { err(o, "bad bssid"); return; } c.have_bssid = 1; }
    if ((v = proto_opt(q, "default_route"))) c.default_route = flag(v, 0);
    char why[200];
    D.hold = 0;
    if (do_join(&c, why, sizeof why)) { set_err("join: %s", why); err(o, "join failed: %s", why); led_apply(); return; }
    char ip[20], gw[20];
    link_ipstr(ip, sizeof ip, D.L.n.lease.ip); link_ipstr(gw, sizeof gw, D.L.n.lease.gw);
    fprintf(o, "OK\n");
    kv(o, "ssid", "%s", c.ssid);
    kv(o, "channel", "%d", D.L.s.channel);
    kv(o, "security", "%s", link_sec_str(D.L.sec));
    kv(o, "pairwise", "%s", link_cipher_str(D.L.pw_cipher));
    kv(o, "ip", "%s", ip); kv(o, "gateway", "%s", gw);
    kv(o, "tun", "%s", D.tun_fd >= 0 ? D.tun_name : (is_root() ? "none" : "link-only"));
}

static void cmd_ping(FILE *o, const proto_req_t *q)
{
    if (!D.linked) { err(o, "not_connected"); return; }
    int count = 4;
    uint32_t target = D.L.n.lease.gw;
    const char *v;
    if ((v = proto_opt(q, "count"))) count = atoi(v);
    if ((v = proto_opt(q, "host"))) {
        struct in_addr a;
        if (inet_pton(AF_INET, v, &a) != 1) { err(o, "bad host"); return; }
        target = ntohl(a.s_addr);
    }
    D.busy = B_OTHER; D.abort_op = 0;
    link_ping_t pr;
    int w = link_ping(&D.L, target, count, &pr);
    D.busy = B_NONE;
    if (w < 0) {
        if (D.L.s.deauth_seen + D.L.s.disassoc_seen) link_lost("deauthenticated during ping");
        err(o, "interrupted_or_deauthenticated"); return;
    }
    if (w > 0) { err(o, "no_reply_to_first_echo"); return; }
    char t[20]; link_ipstr(t, sizeof t, target);
    fprintf(o, "OK\n");
    kv(o, "target", "%s", t);
    kv(o, "sent", "%d", pr.sent); kv(o, "recv", "%d", pr.recv);
    kv(o, "loss_pct", "%d", pr.sent ? 100 - 100 * pr.recv / pr.sent : 100);
    kv(o, "avg_rtt_ms", "%ld", pr.avg_rtt_ms);
}

// ---------------------------------------------------------------- rf on / off, tx power, country
static void rx_count_cb(void *ud, const rtl_frame_t *f) { (void)ud; (void)f; }

static void cmd_rf(FILE *o, const proto_req_t *q)
{
    const char *a = proto_pos(q, 0);
    if (!a || (strcmp(a, "on") && strcmp(a, "off") && strcmp(a, "get"))) { err(o, "usage: rf on|off|get"); return; }
    if (!strcmp(a, "get")) { fprintf(o, "OK\n"); kv(o, "rf", "%s", D.rf_off ? "off" : "on"); return; }
    if (!D.dev) { err(o, "no_device"); return; }
    if (!strcmp(a, "off")) {
        if (D.rf_off) { fprintf(o, "OK\n"); kv(o, "rf", "off"); return; }
        link_drop(1);
        tun_close();
        D.rf_off = 1;
        rf_disable();
        led_apply();
        // Evidence: with the radio off nothing should be heard any more (count frames over 400 ms).
        unsigned long f0 = rtl_rx_stats.frames;
        long t0 = now_ms();
        while (now_ms() - t0 < 400) rtl_rx_poll(&D.r, rx_count_cb, NULL, 50);
        unsigned long heard = rtl_rx_stats.frames - f0;
        LOGF("rf off");
        fprintf(o, "OK\n");
        kv(o, "rf", "off");
        kv(o, "rf_ctrl_reg", "0x%02x", rtl_r8(&D.r, REG_RF_CTRL));
        kv(o, "frames_heard_in_400ms_after_off", "%lu", heard);
        return;
    }
    // on: full re-bring-up (the RF block was shut down), then the auto-join logic rejoins
    if (!D.rf_off) { fprintf(o, "OK\n"); kv(o, "rf", "on"); return; }
    D.rf_off = 0;
    dev_close("rf on: re-initialising");
    dev_try_open();
    if (!D.dev) { err(o, "re-initialisation failed: %s", D.last_error); return; }
    if (D.have_target && !D.hold) { D.attempt = 0; D.next_try = now_ms(); }
    LOGF("rf on");
    fprintf(o, "OK\n");
    kv(o, "rf", "on");
    kv(o, "rf_ctrl_reg", "0x%02x", rtl_r8(&D.r, REG_RF_CTRL));
}

static void cmd_txpower(FILE *o, const proto_req_t *q)
{
    const char *a = proto_pos(q, 0), *v = proto_pos(q, 1);
    if (!a || (strcmp(a, "get") && strcmp(a, "set"))) { err(o, "usage: txpower get | txpower set 0-63"); return; }
    if (!strcmp(a, "set")) {
        char *end;
        long n = v ? strtol(v, &end, 10) : -1;
        if (!v || *end || n < 0 || n > 63) { err(o, "txpower must be 0-63 (0.5 dB steps of the chip's power index)"); return; }
        D.txpower = (int)n; D.txpower_pinned = 1;
        conf_save();
        if (D.dev) {
            if (rtl_pin_tx_power(&D.r, (uint8_t)n)) { err(o, "register write failed"); return; }
        }
    }
    fprintf(o, "OK\n");
    kv(o, "txpower", "%d", D.txpower_pinned ? D.txpower : (D.dev ? D.r.tx_power : RTL_TXPWR_DEFAULT));
    if (D.dev) {
        uint32_t want = (uint32_t)D.r.tx_power * 0x01010101u;
        int ok = 1;
        static const uint16_t regs[] = {0xC20, 0xC24, 0xC28, 0xC2C, 0xC30, 0xC34, 0xC38, 0xC3C, 0xC40, 0xC44};
        for (size_t i = 0; i < sizeof regs / sizeof regs[0]; i++) if (rtl_r32(&D.r, regs[i]) != want) ok = 0;
        kv(o, "reg_c20", "0x%08x", rtl_r32(&D.r, 0xC20));
        kv(o, "readback_matches", "%d", ok);
    }
}

static void cmd_country(FILE *o, const proto_req_t *q)
{
    const char *a = proto_pos(q, 0), *v = proto_pos(q, 1);
    if (!a || (strcmp(a, "get") && strcmp(a, "set"))) { err(o, "usage: country get | country set CC   (CC: %s)", country_list()); return; }
    if (!strcmp(a, "set")) {
        char cc[3];
        if (!v || country_norm(v, cc)) { err(o, "unknown country (known: %s)", country_list()); return; }
        snprintf(D.country, sizeof D.country, "%s", cc);
        conf_save();
        D.have_scan = 0;
        LOGF("country set to %s", D.country);
        if (D.linked && country_chan(D.country, D.L.s.channel) == CC_BLOCKED) {
            LOGF("current channel %d is blocked in %s: leaving", D.L.s.channel, D.country);
            D.have_target = 0;
            link_drop(1);
            tun_close();
        }
    }
    fprintf(o, "OK\n");
    kv(o, "country", "%s", D.country);
    kv(o, "known", "%s", country_list());
}

// ---------------------------------------------------------------- debug
static void cmd_debug(FILE *o, const proto_req_t *q)
{
    const char *a = proto_pos(q, 0), *v = proto_pos(q, 1);
    if (!a) { err(o, "usage: debug drop|unplug|wake|renew|rebind|led"); return; }
    if (!strcmp(a, "drop")) {
        if (!D.linked) { err(o, "not_connected"); return; }
        LOGF("debug: dropping the link (polite deauth), reconnect follows the backoff");
        link_drop(1);
        D.drops++;
        D.attempt = 0; D.next_try = now_ms() + backoff_ms(0);
        led_apply();
        fprintf(o, "OK\n"); kv(o, "next_try_in_ms", "%ld", backoff_ms(0));
        return;
    }
    if (!strcmp(a, "wake")) { on_wake("debug"); fprintf(o, "OK\n"); return; }
    if (!strcmp(a, "unplug")) {
        long ms = v ? atol(v) : 4000;
        if (ms < 0 || ms > 60000) ms = 4000;
        D.sim_unplug_until = now_ms() + ms;
        if (D.dev) dev_close("debug unplug");
        D.next_open = now_ms() + 1000;
        fprintf(o, "OK\n"); kv(o, "replug_in_ms", "%ld", ms);
        return;
    }
    if (!strcmp(a, "renew") || !strcmp(a, "rebind")) {
        if (!D.linked) { err(o, "not_connected"); return; }
        int rb = !strcmp(a, "rebind");
        unsigned before = D.L.n.renews, rbefore = D.L.n.rebinds;
        if (net_dhcp_renew_now(&D.L.n, now_ms(), &D.L.ops, rb)) { err(o, "lease not bound"); return; }
        D.busy = B_OTHER; D.abort_op = 0;
        long end = now_ms() + 6000;
        while (now_ms() < end && D.L.n.renews == before) if (link_pump(&D.L, 100) < 0) break;
        D.busy = B_NONE;
        fprintf(o, "OK\n");
        kv(o, "renews", "%u", D.L.n.renews); kv(o, "rebinds", "%u", D.L.n.rebinds);
        kv(o, "completed", "%d", D.L.n.renews != before);
        kv(o, "as_rebind", "%d", D.L.n.rebinds != rbefore);
        kv(o, "lease_s", "%u", D.L.n.lease.lease_s);
        return;
    }
    if (!strcmp(a, "led")) {
        if (!D.dev) { err(o, "no_device"); return; }
        if (!v || (strcmp(v, "on") && strcmp(v, "off") && strcmp(v, "auto"))) { err(o, "usage: debug led on|off|auto"); return; }
        if (!strcmp(v, "auto")) { D.led_force = -1; led_init(&D.led); led_apply(); }
        else { D.led_force = !strcmp(v, "on"); led_write(&D.r, D.led_force); }
        uint8_t lc; uint32_t gp; int lit;
        led_readback(&D.r, &lc, &gp, &lit);
        fprintf(o, "OK\n");
        kv(o, "forced", "%d", D.led_force); kv(o, "lit_by_register", "%d", lit);
        kv(o, "ledcfg2", "0x%02x", lc); kv(o, "gpio_pin_ctrl_2", "0x%08x", gp);
        return;
    }
    err(o, "unknown debug command");
}

// ---------------------------------------------------------------- dispatch
typedef enum { K_INLINE, K_ABORT, K_RADIO } kind_t;

static kind_t kind_of(const proto_req_t *q)
{
    const char *c = q->cmd, *a = proto_pos(q, 0);
    if (!strcmp(c, "status") || !strcmp(c, "profile") || !strcmp(c, "country") || !strcmp(c, "autojoin")) return K_INLINE;
    if (!strcmp(c, "txpower")) return K_INLINE;
    if (!strcmp(c, "leave") || !strcmp(c, "quit")) return K_ABORT;
    if (!strcmp(c, "rf") && a && !strcmp(a, "off")) return K_ABORT;
    if (!strcmp(c, "debug") && a && (!strcmp(a, "drop") || !strcmp(a, "unplug") || !strcmp(a, "wake"))) return K_ABORT;
    return K_RADIO;
}

// Runs one command; writes the whole response to o.
static void run_cmd(FILE *o, const proto_req_t *q)
{
    const char *c = q->cmd;
    if (!strcmp(c, "status")) cmd_status(o);
    else if (!strcmp(c, "scan")) cmd_scan(o, q);
    else if (!strcmp(c, "join")) cmd_join(o, q);
    else if (!strcmp(c, "leave")) { do_leave(); fprintf(o, "OK\n"); kv(o, "state", "%s", state_name[cur_state()]); }
    else if (!strcmp(c, "ping")) cmd_ping(o, q);
    else if (!strcmp(c, "rf")) cmd_rf(o, q);
    else if (!strcmp(c, "txpower")) cmd_txpower(o, q);
    else if (!strcmp(c, "country")) cmd_country(o, q);
    else if (!strcmp(c, "profile")) cmd_profile(o, q);
    else if (!strcmp(c, "debug")) cmd_debug(o, q);
    else if (!strcmp(c, "autojoin")) {
        const char *a = proto_pos(q, 0);
        if (a && (!strcmp(a, "on") || !strcmp(a, "off"))) { D.autojoin_on = !strcmp(a, "on"); if (D.autojoin_on) { D.hold = 0; D.attempt = 0; D.next_try = 0; } }
        else if (a && strcmp(a, "get")) { err(o, "usage: autojoin on|off|get"); return; }
        fprintf(o, "OK\n"); kv(o, "autojoin", "%d", D.autojoin_on); kv(o, "hold", "%d", D.hold);
    }
    else if (!strcmp(c, "quit")) { D.stop_req = 1; fprintf(o, "OK\n"); }
    else err(o, "unknown command %s (try: status scan join leave ping rf txpower country profile autojoin debug quit)", c);
}

static struct { int used, fd; char line[PROTO_LINE + 1]; } defer;

// Read one request line from fd (waits at most 300 ms for it). Returns the length or -1.
static int read_line(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    long end = now_ms() + 300;
    while (n + 1 < cap) {
        struct pollfd p = { fd, POLLIN, 0 };
        long left = end - now_ms();
        if (left <= 0 || poll(&p, 1, (int)left) <= 0) return -1;
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r <= 0) return -1;
        char *nl = memchr(buf + n, '\n', r);
        n += r;
        if (nl) { buf[nl - buf] = 0; return (int)(nl - buf); }
    }
    return -1;
}

// Handle one request line on fd. busy = we are inside a long job (called from the rx hook). Closes fd unless it was deferred.
static void handle(int fd, const char *line, int busy)
{
    proto_req_t q;
    FILE *o = NULL;
    if (proto_parse(line, &q)) { o = fdopen(fd, "w"); if (o) { fprintf(o, "ERR malformed request\n"); fclose(o); } else close(fd); return; }
    if (busy) {
        kind_t k = kind_of(&q);
        if (k != K_INLINE) {
            if (defer.used) { o = fdopen(fd, "w"); if (o) { fprintf(o, "ERR busy (another command is waiting)\n"); fclose(o); } else close(fd); return; }
            if (k == K_ABORT || D.bg) {
                D.abort_op = 1;
                defer.used = 1; defer.fd = fd; snprintf(defer.line, sizeof defer.line, "%s", line);
                return;
            }
            o = fdopen(fd, "w");
            if (o) { fprintf(o, "ERR busy_%s (try again when it is done, or leave / rf off to abort)\n", D.busy == B_SCAN ? "scanning" : D.busy == B_JOIN ? "joining" : "working"); fclose(o); } else close(fd);
            return;
        }
    }
    o = fdopen(fd, "w");
    if (!o) { close(fd); return; }
    run_cmd(o, &q);
    fclose(o);
}

static void accept_one(int busy)
{
    int fd = accept(D.lfd, NULL, NULL);
    if (fd < 0) return;
    uid_t u; gid_t g;
    if (getpeereid(fd, &u, &g) || (u != 0 && u != geteuid() && u != D.sock_uid)) { close(fd); return; }
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    char line[PROTO_LINE + 1];
    if (read_line(fd, line, sizeof line) < 0) { close(fd); return; }
    handle(fd, line, busy);
}

static void serve_ctl(int timeout_ms, int busy)
{
    struct pollfd p = { D.lfd, POLLIN, 0 };
    while (poll(&p, 1, timeout_ms) > 0 && (p.revents & POLLIN)) { accept_one(busy); timeout_ms = 0; }
}

static void rx_idle_hook(void *ud)
{
    (void)ud;
    if (D.in_hook) return;
    D.in_hook = 1;
    serve_ctl(0, 1);
    if (D.dev && !rtl_usb_dead && D.led_force < 0) { led_set_mode(&D.led, want_led(), now_ms()); led_tick(&D.led, &D.r, now_ms()); }
    D.in_hook = 0;
}

static void run_deferred(void)
{
    if (!defer.used) return;
    int fd = defer.fd;
    char line[PROTO_LINE + 1];
    snprintf(line, sizeof line, "%s", defer.line);
    defer.used = 0;
    D.abort_op = 0;
    handle(fd, line, 0);
}

// ---------------------------------------------------------------- main loop pieces
static void tun_pump(void)
{
    uint8_t pkt[2048];
    for (int k = 0; k < 16; k++) {
        int n = tun_read(D.tun_fd, pkt, sizeof pkt);
        if (n < 0) break;
        if (n == 0) continue;
        if (net_tx_ip(&D.L.n, pkt, n, now_ms(), &D.L.ops) == 0) D.L.st_tun_tx++; else D.L.st_tun_drop++;
    }
}

static void connected_tick(void)
{
    int rc = link_pump(&D.L, 20);
    if (D.tun_fd >= 0) tun_pump();
    if (D.L.st_dec_ok != D.last_dec_ok || D.L.st_tun_tx != D.last_tun) {
        D.last_dec_ok = D.L.st_dec_ok; D.last_tun = D.L.st_tun_tx;
        led_activity(&D.led, now_ms());
    }
    led_apply();
    if (rtl_usb_dead) return;
    if (rc < 0 || D.L.s.deauth_seen + D.L.s.disassoc_seen) {
        link_lost(D.L.s.deauth_seen ? "deauthenticated" : "disassociated");
        return;
    }
    if (D.L.s.last_rx_ms && now_ms() - D.L.s.last_rx_ms > LOSS_SILENCE_MS) { link_lost("AP silent"); return; }
    if (!D.L.n.configured) { link_lost("DHCP lease lost"); return; }
    if (D.tun_fd >= 0 || is_root()) {
        char ip[20]; link_ipstr(ip, sizeof ip, D.L.n.lease.ip);
        if (strcmp(ip, D.tun_ip)) tun_sync();
    }
}

static int visible_cb(void *ctx, const profile_t *p)
{
    (void)ctx;
    if (p->hidden) return 1;
    return scan_find(p->ssid, NULL) != NULL;
}

static void idle_tick(void)
{
    if (!D.dev || D.rf_off || D.hold || D.linked || defer.used) return;
    long now = now_ms();
    if (now < D.next_try) return;
    char why[200];
    if (D.have_target) {
        // reconnect: first try the remembered channel, later attempts scan again (the AP may have moved)
        conn_t c = D.target;
        if (D.attempt >= 1) c.channel = 0;
        LOGF("reconnect attempt %d to %s", D.attempt + 1, c.ssid);
        D.bg = 1;
        int rc = do_join(&c, why, sizeof why);
        D.bg = 0;
        if (rc == 0) { D.reconnects++; D.attempt = 0; return; }
        if (D.hold || defer.used || !D.have_target) return;
        D.attempt++;
        D.next_try = now_ms() + backoff_ms(D.attempt);
        set_err("reconnect: %s", why);
        LOGF("reconnect failed (%s); next in %ld ms", why, backoff_ms(D.attempt));
        if (D.attempt >= 3 && D.autojoin_on) { LOGF("giving up the remembered connection; back to auto-join"); D.have_target = 0; D.attempt = 0; D.next_try = 0; }
        return;
    }
    if (!D.autojoin_on) return;
    int any = 0;
    for (int i = 0; i < D.profiles.n; i++) if (D.profiles.p[i].autojoin) any = 1;
    if (!any) return;
    D.bg = 1;
    int rc = do_scan(0, 160, 1);
    D.bg = 0;
    if (rc != 0 || defer.used) { D.next_try = now_ms() + (rc < 0 ? 2000 : 0); return; }
    int idx = profiles_pick(&D.profiles, visible_cb, NULL, D.skip_ssid[0] ? D.skip_ssid : NULL);
    if (idx < 0) { D.skip_ssid[0] = 0; D.next_try = now_ms() + 8000; return; }
    conn_t c;
    conn_from_profile(&c, &D.profiles.p[idx]);
    LOGF("auto-join: %s", c.ssid);
    D.bg = 1;
    rc = do_join(&c, why, sizeof why);
    D.bg = 0;
    if (rc == 0) { D.attempt = 0; return; }
    if (D.hold || defer.used) return;
    D.attempt++;
    snprintf(D.skip_ssid, sizeof D.skip_ssid, "%s", c.ssid);
    D.next_try = now_ms() + backoff_ms(D.attempt - 1);
    set_err("auto-join %s: %s", c.ssid, why);
    LOGF("auto-join failed (%s); next in %ld ms", why, backoff_ms(D.attempt - 1));
}

static void on_sig(int s) { (void)s; D.stop_req = 1; D.abort_op = 1; }

static int open_socket(void)
{
    struct sockaddr_un a;
    if (strlen(D.sock) >= sizeof a.sun_path) { fprintf(stderr, "awusd: socket path too long\n"); return -1; }
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", D.sock);
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe >= 0 && connect(probe, (struct sockaddr *)&a, sizeof a) == 0) { close(probe); fprintf(stderr, "awusd: another daemon already listens on %s\n", D.sock); return -1; }
    if (probe >= 0) close(probe);
    unlink(D.sock);
    D.lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (D.lfd < 0) return -1;
    mode_t old = umask(077);
    int rc = bind(D.lfd, (struct sockaddr *)&a, sizeof a);
    umask(old);
    if (rc || listen(D.lfd, 8)) { fprintf(stderr, "awusd: cannot listen on %s: %s\n", D.sock, strerror(errno)); return -1; }
    chmod(D.sock, 0600);
    if (is_root() && D.sock_uid) chown(D.sock, D.sock_uid, (gid_t)-1);
    return 0;
}

static void usage(FILE *o)
{
    fprintf(o, "usage: awusd [--sock PATH] [--profiles PATH] [--log PATH] [--sock-uid UID] [--no-autojoin]\n"
               "  Runs in the foreground (launchd keeps it alive). Control it with awusctl.\n"
               "  socket: /var/run/awusd.sock as root, else $TMPDIR/awusd.sock (mode 0600)\n"
               "  profiles: /var/db/awusd/profiles.json as root, else ~/Library/Application Support/awusd/profiles.json (mode 0600)\n"
               "  log (no secrets): /var/log/awusd.log as root, else /tmp/awusd.log\n");
}

int main(int argc, char **argv)
{
    const char *sock = NULL, *prof = NULL, *logp = NULL;
    D.autojoin_on = 1; D.tun_fd = -1; D.led_force = -1;
    snprintf(D.country, sizeof D.country, "00");
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--sock") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--profiles") && i + 1 < argc) prof = argv[++i];
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logp = argv[++i];
        else if (!strcmp(argv[i], "--sock-uid") && i + 1 < argc) D.sock_uid = (uid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-autojoin")) D.autojoin_on = 0;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(stdout); return 0; }
        else { fprintf(stderr, "awusd: unknown or incomplete option %s\n", argv[i]); usage(stderr); return 2; }
    }
    if (sock) snprintf(D.sock, sizeof D.sock, "%s", sock); else if (proto_sock_path(D.sock, sizeof D.sock)) return 2;
    if (prof) snprintf(D.profiles_path, sizeof D.profiles_path, "%s", prof);
    else if (is_root()) snprintf(D.profiles_path, sizeof D.profiles_path, "/var/db/awusd/profiles.json");
    else { const char *h = getenv("HOME"); snprintf(D.profiles_path, sizeof D.profiles_path, "%s/Library/Application Support/awusd/profiles.json", h ? h : "/tmp"); }
    {
        char dir[512]; snprintf(dir, sizeof dir, "%s", D.profiles_path);
        char *sl = strrchr(dir, '/'); if (sl) *sl = 0; else strcpy(dir, ".");
        snprintf(D.conf_path, sizeof D.conf_path, "%s/awusd.conf", dir);
    }
    const char *lp = logp ? logp : (is_root() ? "/var/log/awusd.log" : "/tmp/awusd.log");
    D.logf = fopen(lp, "a");
    if (D.logf) { fchmod(fileno(D.logf), 0600); }
    freopen("/dev/null", "r", stdin);
    if (D.logf) { dup2(fileno(D.logf), 2); }
    D.t_start = now_ms();
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sg; memset(&sg, 0, sizeof sg); sg.sa_handler = on_sig; sigemptyset(&sg.sa_mask);
    sigaction(SIGINT, &sg, NULL); sigaction(SIGTERM, &sg, NULL);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    conf_load();
    if (profiles_load(D.profiles_path, &D.profiles)) { fprintf(stderr, "awusd: cannot read %s (corrupt?)\n", D.profiles_path); return 1; }
    if (open_socket()) return 1;
    rtl_rx_idle = rx_idle_hook;
    LOGF("awusd started: socket %s, profiles %s (%d), country %s, root=%d", D.sock, D.profiles_path, D.profiles.n, D.country, is_root());
    printf("awusd: listening on %s\n", D.sock);
    fflush(stdout);

    while (!D.stop_req) {
        wake_check();
        if (D.dev && rtl_usb_dead) dev_close("USB device gone (unplugged)");
        run_deferred();
        if (!D.dev) {
            serve_ctl(100, 0);
            if (now_ms() >= D.next_open) { D.next_open = now_ms() + 1000; dev_try_open(); }
            continue;
        }
        if (D.rf_off) { serve_ctl(100, 0); led_apply(); continue; }
        if (D.linked) { serve_ctl(0, 0); connected_tick(); continue; }
        serve_ctl(50, 0);
        if (D.dev && now_ms() - D.last_live > 1000) { D.last_live = now_ms(); (void)rtl_r8(&D.r, 0x0); }   // notice an unplug while idle
        idle_tick();
        led_apply();
    }
    LOGF("shutting down");
    if (defer.used) { close(defer.fd); defer.used = 0; }
    if (D.dev) {
        if (D.linked) link_leave(&D.L);
        if (!rtl_usb_dead) { led_write(&D.r, 0); }
    }
    tun_close();
    if (D.dev) rtl_close(&D.r);
    close(D.lfd);
    unlink(D.sock);
    return 0;
}
