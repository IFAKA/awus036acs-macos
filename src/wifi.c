// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
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
#include "link.h"

#define now_ms link_now_ms
static long T0;
#define LOG(...) do { fprintf(stderr, "[%6ldms] ", now_ms() - T0); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

static link_t L;
#define S (L.s)
#define N (L.n)
static volatile sig_atomic_t stop_req;
static void on_sig(int s) { (void)s; stop_req = 1; }

static const char *stage = "STAGE5B";
static void fail(const char *step, const char *reason) { printf("%s FAIL %s %s\n", stage, step, reason); }
#define ipstr link_ipstr

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
    LOG("stats: dec_ok=%lu dec_fail=%lu replay=%lu no_key=%lu clear_drop=%lu tx_enc=%lu data_rx=%lu prot_rx=%lu group_rx=%lu tun_rx=%lu tun_tx=%lu tun_drop=%lu", L.st_dec_ok, L.st_dec_fail, L.st_replay, L.st_no_key,
        L.st_clear_drop, L.st_tx_enc, S.data_rx, S.prot_rx, S.group_rx, L.st_tun_rx, L.st_tun_tx, L.st_tun_drop);
    printf("tx: usb_completed=%lu chip_tx_reports=%lu ok=%lu retry_over=%lu\n", rtl_tx_stats.completed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over);
}

int main(int argc, char **argv)
{
    int hs_rate = 60, data_rate = 60;
    const char *psk;
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
    link_init(&L, &r);
    L.t0 = T0; L.out = stdout; L.stop = &stop_req;
    link_cfg_t cfg = { .ssid = ssid, .bssid = have_b ? bssid : NULL, .channel = ch, .sec = LINK_SEC_WPA2, .key = psk,
                       .hs_rate = hs_rate, .data_rate = data_rate };
    char ips[20], gws[20], masks[20], dnss[80] = "";
    if (link_join(&r, &cfg, &L)) { fail(L.fail_step, L.fail_reason); goto out; }

    ipstr(ips, sizeof ips, N.lease.ip); ipstr(gws, sizeof gws, N.lease.gw); ipstr(masks, sizeof masks, N.lease.mask);
    for (int i = 0; i < N.lease.ndns; i++) { char t[20]; ipstr(t, sizeof t, N.lease.dns[i]); strncat(dnss, i ? "," : "", sizeof dnss - strlen(dnss) - 1); strncat(dnss, t, sizeof dnss - strlen(dnss) - 1); }
    printf("dhcp lease ip=%s gw=%s dns=%s\n", ips, gws, dnss);

    if (tun_mode) {
        uint8_t pkt[2048]; int rejoins = 0;
        L.tun_fd = tun_open(tun_name);
        if (L.tun_fd < 0) {
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
                int n = tun_read(L.tun_fd, pkt, sizeof pkt);
                if (n < 0) break;
                if (n == 0) continue;
                if (net_tx_ip(&N, pkt, n, now_ms(), &L.ops) == 0) L.st_tun_tx++; else L.st_tun_drop++;
            }
            net_tick(&N, now_ms(), &L.ops);
            if (now_ms() >= L.t_next_null) { L.t_next_null = now_ms() + 15000; int rc = sta_send_null(&S); LOG("keepalive null rc=%d", rc); }
            if (S.deauth_seen + S.disassoc_seen) {
                printf("AP %s reason=%d: re-joining\n", S.deauth_seen ? "deauth" : "disassoc", S.deauth_seen ? S.deauth_reason : S.disassoc_reason);
                int ok = 0;
                while (!stop_req && rejoins < 3) {
                    rejoins++;
                    printf("rejoin %d/3\n", rejoins);
                    if (link_rejoin(&L) == 0) { ok = 1; break; }
                    printf("rejoin %d/3 failed: %s %s\n", rejoins, L.fail_step, L.fail_reason);
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
    uint32_t ping_target = N.lease.gw;
    if (ping_host) {
        unsigned a, bb, c, d;
        if (sscanf(ping_host, "%u.%u.%u.%u", &a, &bb, &c, &d) != 4) { fail("ping", "bad_host"); goto out; }
        ping_target = a << 24 | bb << 16 | c << 8 | d;
    }
    link_ping_t pr;
    int w = link_ping(&L, ping_target, 6, &pr);
    if (w < 0) { snprintf(b, sizeof b, "ap_deauth reason=%d", S.deauth_reason); fail("ping", b); goto out; }
    if (w > 0) {
        snprintf(b, sizeof b, "no_echo_reply dec_ok=%lu dec_fail=%lu replay=%lu tx_enc=%lu data_rx=%lu prot_rx=%lu", L.st_dec_ok, L.st_dec_fail, L.st_replay, L.st_tx_enc, S.data_rx, S.prot_rx);
        fail("ping", b); goto out;
    }
    long first_rtt = pr.first_rtt_ms;
    int got = pr.recv;
    printf("ping %s: sent 6 recv %d loss %d%% avg_rtt %ldms\n", gws, got, (6 - got) * 100 / 6, pr.avg_rtt_ms);
    printf("STAGE5B OK ip=%s gw=%s dns=%s rtt_ms=%ld\n", ips, gws, dnss, first_rtt);
    ret = 0;
    if (listen > 0) {
        long end = now_ms() + listen * 1000L;
        while (now_ms() < end) if (link_pump(&L, 100) < 0) { printf("listen: AP deauth reason=%d\n", S.deauth_reason); break; }
        printf("listen done assoc=%d\n", S.associated);
    }
out:
    if (L.tun_fd >= 0) { del_routes(); close(L.tun_fd); L.tun_fd = -1; }
    print_stats();
    rtl_close(&r);
    return ret;
}
