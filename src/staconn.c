// Stage 5A CLI: join our AP (probe, open auth, association) and watch data frames.
//   staconn --ssid S [--bssid xx:..] --ch N [--listen SECS]
// Final line: STAGE5A OK assoc aid=N | STAGE5A FAIL <step> <status/reason>. Log: /tmp/staconn.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtl.h"
#include "mac.h"
#include "tx.h"
#include "bringup.h"
#include "sta.h"

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

static void on_data(void *ud, const uint8_t *d, int len, const rtl_frame_t *f)
{
    sta_t *s = ud;
    static int shown, eap_shown;
    int hl = 24 + ((d[0] & 0x80) ? 2 : 0);
    if (shown < 12) {
        shown++;
        printf("  rx data fc=%02x%02x len=%d da=%02x:%02x:%02x:%02x:%02x:%02x %s swdec=%d sec=%d rate=%d rssi=%d", d[0], d[1], len, d[4], d[5], d[6], d[7], d[8], d[9],
               (d[1] & 0x40) ? "PROTECTED" : "clear", f->swdec, f->security, f->rate, f->rssi_dbm);
        if ((d[1] & 0x40) && len >= hl + 8) printf(" ccmp: pn0=%02x pn1=%02x b3=%02x extiv=%d", d[hl], d[hl + 1], d[hl + 3], !!(d[hl + 3] & 0x20));
        printf("\n");
    }
    if (!eap_shown && s->eapol_rx && s->eapol_keyinfo >= 0) { eap_shown = 1; printf("  EAPOL-Key from AP: key_info=0x%04x\n", s->eapol_keyinfo); }
}

int main(int argc, char **argv)
{
    const char *ssid = NULL; uint8_t bssid[6]; int have_b = 0, ch = 0, listen = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--ssid") && i + 1 < argc) ssid = argv[++i];
        else if (!strcmp(argv[i], "--bssid") && i + 1 < argc)
            have_b = sscanf(argv[++i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) == 6;
        else if (!strcmp(argv[i], "--ch") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) listen = atoi(argv[++i]);
    }
    if (!ssid || !ch) { fprintf(stderr, "usage: staconn --ssid S [--bssid xx:xx:xx:xx:xx:xx] --ch N [--listen SECS]\n"); return 2; }
    rtl_t r = {0};
    if (!freopen("/tmp/staconn.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    r.verbose = 1;
    char b[160]; const char *step;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) { printf("STAGE5A FAIL %s %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { printf("STAGE5A FAIL set_monitor\n"); return 1; }
    r.verbose = 0;
    srand(time(NULL) ^ getpid());
    sta_t s;
    sta_init(&s, &r, ssid, have_b ? bssid : NULL, ch);
    printf("sa=%02x:%02x:%02x:%02x:%02x:%02x ssid=%s ch=%d\n", s.mac[0], s.mac[1], s.mac[2], s.mac[3], s.mac[4], s.mac[5], ssid, ch);
    int ret = 1;
    if (sta_scan(&s, 4000)) { printf("STAGE5A FAIL scan no_probe_response_or_beacon\n"); goto out; }
    printf("ap bssid=%02x:%02x:%02x:%02x:%02x:%02x cap=0x%04x rates=%d+%d rsn_ie=%d bytes rssi=%d\n", s.bssid[0], s.bssid[1], s.bssid[2], s.bssid[3], s.bssid[4], s.bssid[5],
           s.ap_cap, s.nrates, s.nxrates, s.rsn_len, s.rssi);
    if (s.rsn_len) { printf("rsn:"); for (int i = 0; i < s.rsn_len; i++) printf("%02x", s.rsn[i]); printf("\n"); }
    if (sta_auth(&s)) { printf("STAGE5A FAIL auth %s\n", s.last_status < 0 ? "timeout" : (snprintf(b, sizeof b, "status=%d", s.last_status), b)); goto out; }
    if (sta_assoc(&s)) { printf("STAGE5A FAIL assoc %s\n", s.last_status < 0 ? "timeout" : (snprintf(b, sizeof b, "status=%d", s.last_status), b)); goto out; }
    printf("STAGE5A OK assoc aid=%d\n", s.aid);
    ret = 0;
    if (listen > 0) {
        long t0 = now_ms(), next_null = t0 + 10000, end = t0 + listen * 1000L;
        int seen_deauth = 0;
        while (now_ms() < end) {
            sta_poll(&s, 100, on_data, &s);
            if (now_ms() >= next_null && s.associated && !getenv("NONULL")) { next_null += 10000; int e = sta_send_null(&s); printf("[%lds] null-data tx rc=%d\n", (now_ms() - t0) / 1000, e); }
            if ((s.deauth_seen || s.disassoc_seen) && !seen_deauth) {
                seen_deauth = 1;
                printf("[%ldms] AP %s reason=%d\n", now_ms() - t0, s.deauth_seen ? "DEAUTH" : "DISASSOC", s.deauth_seen ? s.deauth_reason : s.disassoc_reason);
            }
        }
        printf("listen %ds: data=%lu group=%lu protected=%lu with_extiv=%lu eapol_key=%lu last_keyinfo=%d deauth=%d(reason %d) disassoc=%d(reason %d) assoc_now=%d\n", listen,
               s.data_rx, s.group_rx, s.prot_rx, s.prot_extiv, s.eapol_rx, s.eapol_keyinfo, s.deauth_seen, s.deauth_reason, s.disassoc_seen, s.disassoc_reason, s.associated);
    }
out:
    printf("tx: usb_completed=%lu chip_tx_reports=%lu ok=%lu retry_over=%lu\n", rtl_tx_stats.completed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over);
    rtl_close(&r);
    return ret;
}
