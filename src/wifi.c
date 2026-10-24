// Stage 5B/5C CLI: full WPA2-PSK join (4-way handshake, software CCMP, ARP/DHCP, ICMP ping).
//   5B (default): join, DHCP, ping. Final line: STAGE5B OK ip=.. gw=.. dns=.. rtt_ms=N | STAGE5B FAIL <step> <reason>.
//   5C (--tun, needs root): after DHCP, bridge to a utun with host routes only (never the default route).
// The passphrase is read from the environment only (TEST_PSK or --psk-env NAME), never from argv.
// Log (no secrets): /tmp/wifi.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "rtl.h"
#include "mac.h"
#include "tx.h"
#include "bringup.h"
#include "sta.h"
#include "wpa.h"
#include "net.h"
#include "tun.h"

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
static long T0;
#define LOG(...) do { fprintf(stderr, "[%6ldms] ", now_ms() - T0); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

static sta_t S;
static wpa_t W;
static net_t N;
static net_ops_t OPS;

static int hs_rate = 60, data_rate = 60;
static int m1_count, handshake_done, rsn_mismatch, tk_ready;
static long t_assoc, t_m1, t_hs;
static uint64_t tx_pn = 1;
static uint64_t rx_pn[16];           // last accepted PN per TID (pairwise)
static uint8_t gtk_key[4][16]; static int gtk_have[4]; static uint64_t gtk_pn[4];
static unsigned long st_dec_fail, st_replay, st_dec_ok, st_tx_enc, st_clear_drop, st_no_key;

// ping bookkeeping
#define ECHO_ID 0x4157
static uint32_t ping_target;
static long ping_sent_at[64]; static int ping_got[64]; static long ping_rtt[64];
static uint32_t lease_ip;

static void hexs(const uint8_t *p, int n) { for (int i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]); }

// ---- handshake ----
static void send_eapol(const uint8_t *eapol, size_t n, const char *what)
{
    uint8_t body[8 + 512];
    static const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    memcpy(body, llc, 8); memcpy(body + 8, eapol, n);
    int rc = sta_send_data(&S, S.bssid, body, 8 + (int)n, 0, hs_rate);
    LOG("tx EAPOL %s len=%zu rate=%d rc=%d", what, n, hs_rate, rc);
}

static void handle_eapol(const uint8_t *e, size_t el)
{
    uint8_t out[512]; size_t ol = 0; int ev = 0;
    eapol_key_t k;
    if (eapol_key_parse(e, el, &k) == 0) {
        LOG("rx EAPOL key_info=0x%04x replay=%llu kdlen=%zu", k.info, (unsigned long long)k.replay, k.key_data_len);
        if ((k.info & EAPOL_KEY_PAIRWISE) && !(k.info & EAPOL_KEY_MIC)) {
            m1_count++; if (m1_count == 1) t_m1 = now_ms();
            if (m1_count > 1) { hs_rate = (m1_count % 2) ? 60 : 10; LOG("M1 retransmit #%d -> reply rate %d", m1_count, hs_rate); }
        }
    } else LOG("rx EAPOL malformed len=%zu", el);
    int rc = wpa_rx_eapol(&W, e, el, out, &ol, &ev);
    if (rc) { LOG("wpa_rx_eapol rejected rc=%d", rc); return; }
    if (ev & WPA_EV_PTK) {
        if (W.ap_rsn_len != (size_t)S.rsn_len || memcmp(W.ap_rsn, S.rsn, W.ap_rsn_len)) {
            rsn_mismatch = 1;
            LOG("RSN IE in M3 differs from probe response; refusing (not sending M4)");
            LOG("probe rsn: "); hexs(S.rsn, S.rsn_len); fputc('\n', stderr);
            LOG("m3 rsn:    "); hexs(W.ap_rsn, W.ap_rsn_len); fputc('\n', stderr);
            return;
        }
    }
    const char *what = (k.info & EAPOL_KEY_PAIRWISE) ? ((k.info & EAPOL_KEY_MIC) ? "M4" : "M2") : "G2";
    if (ol) send_eapol(out, ol, what);
    if (ev & WPA_EV_PTK) {                 // install the TK only after M4 went out
        tk_ready = 1; tx_pn = 1; memset(rx_pn, 0, sizeof rx_pn);
        LOG("PTK installed (TK)");
    }
    if (ev & WPA_EV_GTK) {
        size_t gl; int gid;
        const uint8_t *g = wpa_get_gtk(&W, &gl, &gid);
        if (g && gl == 16) { memcpy(gtk_key[gid & 3], g, 16); gtk_have[gid & 3] = 1; gtk_pn[gid & 3] = 0; LOG("GTK installed id=%d", gid); }
        else LOG("GTK unusable len=%zu", gl);
    }
    if (W.state == 2 && gtk_have[0] + gtk_have[1] + gtk_have[2] + gtk_have[3] && !handshake_done) {
        handshake_done = 1; t_hs = now_ms();
        LOG("handshake complete");
    }
}

// ---- data RX ----
static void on_data(void *ud, const uint8_t *d, int len, const rtl_frame_t *f)
{
    (void)ud; (void)f;
    int sub = d[0] >> 4, qos = (sub & 8) != 0, ht = (d[1] & 0x80) != 0;
    int hl = 24 + (qos ? 2 : 0) + (ht ? 4 : 0);
    if (len < hl + 8) return;
    const uint8_t *a1 = d + 4, *a3 = d + 16;
    int group = a1[0] & 1;
    if (!(d[1] & 0x40)) {
        if (!memcmp(d + hl, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) { handle_eapol(d + hl + 8, len - hl - 8); return; }
        st_clear_drop++;
        return;
    }
    if (group && !memcmp(a3, S.mac, 6)) return;             // our own broadcast reflected by the AP
    const uint8_t *key; int kid = (d[hl + 3] >> 6) & 3;
    uint64_t *lastpn;
    int tid = qos ? (d[24] & 0x0F) : 0;
    if (group) {
        if (!gtk_have[kid]) { st_no_key++; return; }
        key = gtk_key[kid]; lastpn = &gtk_pn[kid];
    } else {
        key = wpa_get_tk(&W);
        if (!key || !tk_ready) { st_no_key++; return; }
        lastpn = &rx_pn[tid];
    }
    uint8_t plain[2400]; uint64_t pn = 0; int k2 = 0;
    if (len - hl > (int)sizeof plain) return;
    int pl = ccmp_decrypt(key, d, 24 + (qos ? 2 : 0), d + hl, len - hl, plain, &pn, &k2);
    if (pl < 0) {
        st_dec_fail++;
        if (st_dec_fail <= 8) { LOG("ccmp decrypt FAIL fc=%02x%02x len=%d hl=%d group=%d kid=%d tid=%d", d[0], d[1], len, hl, group, kid, tid); }
        return;
    }
    if (pn <= *lastpn) { st_replay++; LOG("replay reject pn=%llu last=%llu", (unsigned long long)pn, (unsigned long long)*lastpn); return; }
    *lastpn = pn;
    st_dec_ok++;
    net_rx(&N, plain, pl, now_ms(), &OPS);
}

// ---- data TX ----
static void ops_tx(void *ctx, const uint8_t dst[6], const uint8_t *payload, size_t len)
{
    (void)ctx;
    uint8_t hdr[24] = {0}, out[2400];
    if (!tk_ready || len > 1700) return;
    hdr[0] = 0x08; hdr[1] = 0x41;
    memcpy(hdr + 4, S.bssid, 6); memcpy(hdr + 10, S.mac, 6); memcpy(hdr + 16, dst, 6);
    int n = ccmp_encrypt(wpa_get_tk(&W), hdr, 24, tx_pn++, 0, payload, len, out);
    if (n < 0) return;
    st_tx_enc++;
    int rc = sta_send_data(&S, dst, out, n, 1, data_rate);
    if (rc) LOG("data tx rc=%d", rc);
}

static int tun_fd = -1;
static unsigned long st_tun_rx, st_tun_tx, st_tun_drop;

static void ops_to_tun(void *ctx, const uint8_t *p, size_t len)
{
    (void)ctx;
    if (tun_fd >= 0) {
        if (tun_write(tun_fd, p, len) == 0) st_tun_rx++; else st_tun_drop++;
        return;
    }
    if (len < 28 || (p[0] >> 4) != 4) return;
    int ihl = (p[0] & 15) * 4;
    if (p[9] != 1 || (size_t)ihl + 8 > len) return;
    const uint8_t *ic = p + ihl;
    if (ic[0] != 0) return;
    int id = ic[4] << 8 | ic[5], seq = ic[6] << 8 | ic[7];
    if (id != ECHO_ID || seq < 0 || seq >= 64 || ping_got[seq]) return;
    ping_got[seq] = 1; ping_rtt[seq] = now_ms() - ping_sent_at[seq];
    LOG("echo reply seq=%d rtt=%ldms", seq, ping_rtt[seq]);
}

static void ops_lease(void *ctx, const net_lease_t *l, int up)
{
    (void)ctx;
    if (up) { lease_ip = l->ip; LOG("lease up ip=%08x gw=%08x", l->ip, l->gw); }
    else LOG("lease down");
}

static volatile sig_atomic_t stop_req;
static void on_sig(int s) { (void)s; stop_req = 1; }

// ---- main loop helpers ----
static long t_next_null;
static int pump(int ms)
{
    long end = now_ms() + ms;
    int dseen = S.deauth_seen + S.disassoc_seen;
    do {
        sta_poll(&S, 20, NULL, NULL);
        if (S.deauth_seen + S.disassoc_seen != dseen) return -1;
        if (stop_req) return -1;
        if (handshake_done) {
            net_tick(&N, now_ms(), &OPS);
            if (now_ms() >= t_next_null) { t_next_null = now_ms() + 15000; int rc = sta_send_null(&S); LOG("keepalive null rc=%d", rc); }
        }
    } while (now_ms() < end);
    return 0;
}

static const char *stage = "STAGE5B";
static void fail(const char *step, const char *reason) { printf("%s FAIL %s %s\n", stage, step, reason); }

static void send_ping(int seq)
{
    uint8_t p[20 + 8 + 32] = {0};
    p[0] = 0x45; p[2] = 0; p[3] = sizeof p; p[4] = 0x70; p[5] = seq; p[8] = 64; p[9] = 1;
    p[12] = lease_ip >> 24; p[13] = lease_ip >> 16; p[14] = lease_ip >> 8; p[15] = lease_ip;
    p[16] = ping_target >> 24; p[17] = ping_target >> 16; p[18] = ping_target >> 8; p[19] = ping_target;
    uint16_t c = net_cksum(p, 20); p[10] = c >> 8; p[11] = c;
    uint8_t *ic = p + 20;
    ic[0] = 8; ic[4] = ECHO_ID >> 8; ic[5] = ECHO_ID & 0xFF; ic[6] = seq >> 8; ic[7] = seq;
    for (int i = 0; i < 32; i++) ic[8 + i] = 0x41 + i;
    c = net_cksum(ic, 40); ic[2] = c >> 8; ic[3] = c;
    ping_sent_at[seq] = now_ms();
    int rc = net_tx_ip(&N, p, sizeof p, now_ms(), &OPS);
    LOG("ping seq=%d tx rc=%d", seq, rc);
}

static int wait_echo(int seq, int ms)
{
    long end = now_ms() + ms;
    while (now_ms() < end && !ping_got[seq]) if (pump(20) < 0) return -1;
    return ping_got[seq] ? 0 : 1;
}

static void ipstr(char *b, size_t n, uint32_t a) { snprintf(b, n, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255); }

// ---- join (scan, auth, assoc, 4-way, DHCP). On failure sets jstep/jreason and returns -1. ----
static const char *psk;
static char jstep[32], jreason[200];
static int jfail(const char *step, const char *reason) { snprintf(jstep, sizeof jstep, "%s", step); snprintf(jreason, sizeof jreason, "%s", reason); return -1; }
static int jfail_status(const char *step)
{
    char b[40];
    if (S.last_status < 0) return jfail(step, "timeout");
    snprintf(b, sizeof b, "status=%d", S.last_status);
    return jfail(step, b);
}
static const uint8_t our_rsn[] = {48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 2, 0, 0};

static int join_once(void)
{
    char b[200];
    // fresh state for every attempt
    handshake_done = rsn_mismatch = tk_ready = m1_count = 0;
    memset(gtk_key, 0, sizeof gtk_key); memset(gtk_have, 0, sizeof gtk_have); memset(gtk_pn, 0, sizeof gtk_pn);
    memset(rx_pn, 0, sizeof rx_pn); tx_pn = 1; hs_rate = 60;
    S.deauth_seen = S.disassoc_seen = 0; S.associated = 0;
    if (sta_scan(&S, 4000)) return jfail("scan", "no_probe_response");
    if (!S.rsn_len) return jfail("scan", "ap_has_no_rsn_ie");
    LOG("ap bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d", S.bssid[0], S.bssid[1], S.bssid[2], S.bssid[3], S.bssid[4], S.bssid[5], S.rssi);
    wpa_init(&W, psk, (const uint8_t *)S.ssid, strlen(S.ssid), S.bssid, S.mac, our_rsn, sizeof our_rsn);
    net_init(&N, S.mac);
    if (sta_auth(&S)) return jfail_status("auth");
    if (sta_assoc(&S)) return jfail_status("assoc");
    t_assoc = now_ms();
    LOG("associated aid=%d (elapsed counted from here)", S.aid);
    printf("assoc aid=%d\n", S.aid);

    int dseen = S.deauth_seen + S.disassoc_seen;
    long end = now_ms() + 10000;
    while (now_ms() < end && !handshake_done && !rsn_mismatch && !stop_req && S.deauth_seen + S.disassoc_seen == dseen)
        sta_poll(&S, 50, NULL, NULL);
    if (stop_req) return jfail("interrupted", "signal");
    if (rsn_mismatch) return jfail("handshake", "rsn_ie_mismatch");
    if (S.deauth_seen + S.disassoc_seen != dseen) {
        snprintf(b, sizeof b, "ap_%s reason=%d m1_seen=%d state=%d", S.deauth_seen ? "deauth" : "disassoc", S.deauth_seen ? S.deauth_reason : S.disassoc_reason, m1_count, W.state);
        return jfail("handshake", b);
    }
    if (!handshake_done) {
        snprintf(b, sizeof b, "timeout m1_seen=%d state=%d eapol_rx=%lu", m1_count, W.state, S.eapol_rx);
        return jfail("handshake", b);
    }
    printf("handshake ok: M1 rx at %ldms, M4 tx at %ldms (since start)\n", t_m1 - T0, t_hs - T0);
    t_next_null = now_ms() + 15000;

    net_dhcp_start(&N, now_ms(), &OPS);
    end = now_ms() + 20000;
    while (now_ms() < end && !N.configured) if (pump(20) < 0) break;
    if (stop_req) return jfail("interrupted", "signal");
    if (S.deauth_seen + S.disassoc_seen) { snprintf(b, sizeof b, "ap_deauth reason=%d", S.deauth_seen ? S.deauth_reason : S.disassoc_reason); return jfail("dhcp", b); }
    if (!N.configured) {
        snprintf(b, sizeof b, "timeout dec_ok=%lu dec_fail=%lu tx_enc=%lu", st_dec_ok, st_dec_fail, st_tx_enc);
        return jfail("dhcp", b);
    }
    return 0;
}

// Whole-join retry: up to 3 attempts, 1 s apart, on scan/auth/assoc/handshake failures. Not retried: DHCP, RSN mismatch, no RSN IE, signals.
static int join_retry(void)
{
    for (int a = 1; a <= 3 && !stop_req; a++) {
        if (join_once() == 0) return 0;
        int retryable = !strcmp(jstep, "scan") ? !strcmp(jreason, "no_probe_response")
                      : (!strcmp(jstep, "auth") || !strcmp(jstep, "assoc"))
                      || (!strcmp(jstep, "handshake") && strcmp(jreason, "rsn_ie_mismatch"));
        printf("join attempt %d/3 failed: %s %s\n", a, jstep, jreason);
        if (a == 3 || !retryable) return -1;
        sleep(1);
    }
    return -1;
}

// ---- routes (fork/exec, no shell) ----
#define MAX_ROUTES 16
static char route_ip[MAX_ROUTES][16]; static int nroutes;
static char tun_name[16];

static int valid_dq(const char *s)
{
    struct in_addr a; unsigned x[4]; char tail;
    if (!s || strlen(s) > 15 || sscanf(s, "%u.%u.%u.%u%c", &x[0], &x[1], &x[2], &x[3], &tail) != 4) return 0;
    return inet_pton(AF_INET, s, &a) == 1 && a.s_addr != 0;
}

static void add_route(const char *ip)
{
    if (nroutes >= MAX_ROUTES) return;
    if (tun_add_host_route(tun_name, ip) == 0) { snprintf(route_ip[nroutes++], 16, "%s", ip); printf("route add -host %s -interface %s\n", ip, tun_name); }
    else printf("route add %s FAILED\n", ip);
}

static void del_routes(void)
{
    for (int i = 0; i < nroutes; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[] = { "route", "-n", "delete", "-host", route_ip[i], "-interface", tun_name, NULL };
            execv("/sbin/route", argv); _exit(127);
        }
        if (pid > 0) { int st; while (waitpid(pid, &st, 0) < 0 && errno == EINTR) ; }
        printf("route delete -host %s -interface %s\n", route_ip[i], tun_name);
    }
    nroutes = 0;
}

static void usage(FILE *o)
{
    fprintf(o,
        "usage: wifi --ssid S --ch N [--bssid xx:xx:xx:xx:xx:xx] [--psk-env NAME] [options]\n"
        "  The passphrase is read ONLY from the environment: TEST_PSK, or the variable named by --psk-env.\n"
        "  It is never accepted on the command line and never logged.\n"
        "options:\n"
        "  --listen SECS     (non-tun) stay associated SECS seconds after the ping test\n"
        "  --ping IP         (non-tun) ping IP instead of the gateway\n"
        "  --hs-rate 60|10, --rate R   TX rates (advanced)\n"
        "  --tun             (root) after DHCP open a utun, give it our IP, bridge frames both ways\n"
        "  --route IP        (with --tun, repeatable) add a host route for IP via the utun\n"
        "                    The default route and other interfaces are never touched.\n"
        "  --help            this text\n"
        "log (no secrets): /tmp/wifi.log\n"
        "\ncommands to type:\n"
        "  1) no root, join + ping gateway (prints STAGE5B OK):\n"
        "     . /tmp/awus-test.env && ./build/wifi --ssid \"$TEST_SSID\" --bssid aa:bb:cc:dd:ee:ff --ch 7\n"
        "  2) root, tunnel; routes only for the gateway and 1.1.1.1; stop with Ctrl-C:\n"
        "     . /tmp/awus-test.env && sudo --preserve-env=TEST_PSK ./build/wifi --tun --ssid \"$TEST_SSID\" --bssid aa:bb:cc:dd:ee:ff --ch 7 --route 1.1.1.1\n"
        "     then in another terminal:  ping -c 3 1.1.1.1     (and: ping -c 3 <gateway ip>)\n"
        "     Ctrl-C removes the routes it added and closes the utun.\n");
}

static void print_stats(void)
{
    LOG("stats: dec_ok=%lu dec_fail=%lu replay=%lu no_key=%lu clear_drop=%lu tx_enc=%lu data_rx=%lu prot_rx=%lu group_rx=%lu tun_rx=%lu tun_tx=%lu tun_drop=%lu", st_dec_ok, st_dec_fail, st_replay, st_no_key,
        st_clear_drop, st_tx_enc, S.data_rx, S.prot_rx, S.group_rx, st_tun_rx, st_tun_tx, st_tun_drop);
    printf("tx: usb_completed=%lu chip_tx_reports=%lu ok=%lu retry_over=%lu\n", rtl_tx_stats.completed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over);
}

int main(int argc, char **argv)
{
    const char *ssid = NULL, *ping_host = NULL, *psk_env = "TEST_PSK"; uint8_t bssid[6]; int have_b = 0, ch = 0, listen = 0, tun_mode = 0, nuser = 0;
    char user_routes[MAX_ROUTES][16];
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(stdout); return 0; }
        else if (!strcmp(argv[i], "--ssid") && i + 1 < argc) ssid = argv[++i];
        else if (!strcmp(argv[i], "--bssid") && i + 1 < argc)
            have_b = sscanf(argv[++i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) == 6;
        else if (!strcmp(argv[i], "--ch") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) listen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ping") && i + 1 < argc) ping_host = argv[++i];
        else if (!strcmp(argv[i], "--hs-rate") && i + 1 < argc) hs_rate = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) data_rate = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--psk-env") && i + 1 < argc) psk_env = argv[++i];
        else if (!strcmp(argv[i], "--tun")) tun_mode = 1;
        else if (!strcmp(argv[i], "--route") && i + 1 < argc) {
            const char *ip = argv[++i];
            if (!valid_dq(ip) || nuser >= MAX_ROUTES - 1) { fprintf(stderr, "bad --route %s (need a dotted-quad IPv4, max %d)\n", ip, MAX_ROUTES - 1); return 2; }
            snprintf(user_routes[nuser++], 16, "%s", ip);
        } else { fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]); usage(stderr); return 2; }
    }
    if (nuser && !tun_mode) { fprintf(stderr, "--route needs --tun\n"); return 2; }
    psk = getenv(psk_env);
    if (!ssid || !ch || !psk || !*psk) { fprintf(stderr, "missing --ssid/--ch or empty passphrase variable %s (see --help)\n", psk_env); return 2; }
    if (tun_mode) stage = "STAGE5C";
    if (!freopen("/tmp/wifi.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0); setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_sig; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    T0 = now_ms();
    rtl_t r = {0};
    r.verbose = 1;
    char b[160]; const char *step; int ret = 1;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) { fail(step, b); return 1; }
    if (rtl_set_monitor(&r)) { fail("set_monitor", "error"); return 1; }
    r.verbose = 0;
    srand(time(NULL) ^ getpid());
    sta_init(&S, &r, ssid, have_b ? bssid : NULL, ch);
    S.def_cb = on_data;
    LOG("sa=%02x:%02x:%02x:%02x:%02x:%02x", S.mac[0], S.mac[1], S.mac[2], S.mac[3], S.mac[4], S.mac[5]);
    OPS = (net_ops_t){ .ctx = NULL, .tx = ops_tx, .to_tun = ops_to_tun, .lease = ops_lease };
    char ips[20], gws[20], masks[20], dnss[80] = "";
    if (join_retry()) { fail(jstep, jreason); goto out; }

    ipstr(ips, sizeof ips, N.lease.ip); ipstr(gws, sizeof gws, N.lease.gw); ipstr(masks, sizeof masks, N.lease.mask);
    for (int i = 0; i < N.lease.ndns; i++) { char t[20]; ipstr(t, sizeof t, N.lease.dns[i]); strncat(dnss, i ? "," : "", sizeof dnss - strlen(dnss) - 1); strncat(dnss, t, sizeof dnss - strlen(dnss) - 1); }
    printf("dhcp lease ip=%s gw=%s dns=%s\n", ips, gws, dnss);

    if (tun_mode) {
        uint8_t pkt[2048]; int rejoins = 0;
        tun_fd = tun_open(tun_name);
        if (tun_fd < 0) {
            int e = errno;
            snprintf(b, sizeof b, "%s%s", strerror(e), e == EPERM ? " (run with sudo)" : "");
            fail("tun_open", b); goto out;
        }
        if (tun_configure(tun_name, ips, gws, masks)) { fail("tun_configure", "ifconfig/route failed (needs root)"); goto out; }
        printf("route add -host %s -interface %s (by tun_configure)\n", gws, tun_name);
        snprintf(route_ip[nroutes++], 16, "%s", gws);
        for (int i = 0; i < nuser; i++) { if (strcmp(user_routes[i], gws)) add_route(user_routes[i]); }
        printf("TUN UP %s ip=%s gw=%s\n", tun_name, ips, gws);

        while (!stop_req) {
            sta_poll(&S, 10, NULL, NULL);
            for (int k = 0; k < 16; k++) {
                int n = tun_read(tun_fd, pkt, sizeof pkt);
                if (n < 0) break;
                if (n == 0) continue;
                if (net_tx_ip(&N, pkt, n, now_ms(), &OPS) == 0) st_tun_tx++; else st_tun_drop++;
            }
            net_tick(&N, now_ms(), &OPS);
            if (now_ms() >= t_next_null) { t_next_null = now_ms() + 15000; int rc = sta_send_null(&S); LOG("keepalive null rc=%d", rc); }
            if (S.deauth_seen + S.disassoc_seen) {
                printf("AP %s reason=%d: re-joining\n", S.deauth_seen ? "deauth" : "disassoc", S.deauth_seen ? S.deauth_reason : S.disassoc_reason);
                int ok = 0;
                while (!stop_req && rejoins < 3) {
                    rejoins++;
                    printf("rejoin %d/3\n", rejoins);
                    if (join_once() == 0) { ok = 1; break; }
                    printf("rejoin %d/3 failed: %s %s\n", rejoins, jstep, jreason);
                    sleep(1);
                }
                if (stop_req) break;
                if (!ok) { fail("rejoin", "gave up after 3 attempts"); goto out; }
                rejoins = 0;
                char nip[20]; ipstr(nip, sizeof nip, N.lease.ip);
                if (strcmp(nip, ips)) {
                    printf("lease changed %s -> %s; reconfiguring %s\n", ips, nip, tun_name);
                    snprintf(ips, sizeof ips, "%s", nip);
                    if (tun_configure(tun_name, ips, gws, masks)) { fail("tun_configure", "reconfigure failed"); goto out; }
                }
                printf("rejoined ip=%s gw=%s\n", ips, gws);
            }
        }
        printf("%s DONE (signal)\n", stage);
        ret = 0;
        goto out;
    }

    // ICMP echo to the gateway (or --ping host)
    ping_target = N.lease.gw;
    if (ping_host) {
        unsigned a, bb, c, d;
        if (sscanf(ping_host, "%u.%u.%u.%u", &a, &bb, &c, &d) != 4) { fail("ping", "bad_host"); goto out; }
        ping_target = a << 24 | bb << 16 | c << 8 | d;
    }
    send_ping(0);
    int w = wait_echo(0, 3000);
    if (w < 0) { snprintf(b, sizeof b, "ap_deauth reason=%d", S.deauth_reason); fail("ping", b); goto out; }
    if (w > 0) {
        snprintf(b, sizeof b, "no_echo_reply dec_ok=%lu dec_fail=%lu replay=%lu tx_enc=%lu data_rx=%lu prot_rx=%lu", st_dec_ok, st_dec_fail, st_replay, st_tx_enc, S.data_rx, S.prot_rx);
        fail("ping", b); goto out;
    }
    long first_rtt = ping_rtt[0];
    int got = 1; long sum = first_rtt;
    for (int seq = 1; seq <= 5; seq++) {
        send_ping(seq);
        if (wait_echo(seq, 1000) == 0) { got++; sum += ping_rtt[seq]; }
        else if (S.deauth_seen) break;
        if (pump(200) < 0) break;
    }
    printf("ping %s: sent 6 recv %d loss %d%% avg_rtt %ldms\n", gws, got, (6 - got) * 100 / 6, got ? sum / got : -1);
    printf("STAGE5B OK ip=%s gw=%s dns=%s rtt_ms=%ld\n", ips, gws, dnss, first_rtt);
    ret = 0;
    if (listen > 0) {
        long end = now_ms() + listen * 1000L;
        while (now_ms() < end) if (pump(100) < 0) { printf("listen: AP deauth reason=%d\n", S.deauth_reason); break; }
        printf("listen done assoc=%d\n", S.associated);
    }
out:
    if (tun_fd >= 0) { del_routes(); close(tun_fd); tun_fd = -1; }
    print_stats();
    rtl_close(&r);
    return ret;
}
