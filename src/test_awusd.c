// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Unit tests for the daemon's pure parts: country table, profile store, command parser, backoff, LED decision.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "country.h"
#include "profile.h"
#include "proto.h"
#include "led.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void t_country(void)
{
    CHECK(country_known("ES") && country_known("es") && country_known("00") && country_known("US") && country_known("JP"));
    CHECK(!country_known("XX") && !country_known("") && !country_known("USA") && !country_known(NULL));
    CHECK(country_chan("ES", 1) == CC_OK && country_chan("ES", 13) == CC_OK && country_chan("US", 12) == CC_BLOCKED);
    CHECK(country_chan("ES", 14) == CC_BLOCKED && country_chan("JP", 14) == CC_BLOCKED);
    CHECK(country_chan("ES", 36) == CC_OK && country_chan("ES", 48) == CC_OK);
    CHECK(country_chan("ES", 52) == CC_DFS && country_chan("ES", 64) == CC_DFS);
    CHECK(country_chan("ES", 100) == CC_DFS && country_chan("ES", 132) == CC_DFS && country_chan("ES", 140) == CC_DFS);
    CHECK(country_chan("ES", 144) == CC_BLOCKED && country_chan("US", 144) == CC_DFS);
    CHECK(country_chan("ES", 149) == CC_OK && country_chan("ES", 165) == CC_OK && country_chan("JP", 149) == CC_BLOCKED);
    CHECK(country_chan("00", 11) == CC_OK && country_chan("00", 12) == CC_BLOCKED);
    CHECK(country_chan("00", 36) == CC_OK && country_chan("00", 52) == CC_BLOCKED && country_chan("00", 132) == CC_BLOCKED && country_chan("00", 149) == CC_BLOCKED);
    CHECK(country_chan("ZZ", 132) == CC_BLOCKED && country_chan("ZZ", 6) == CC_OK);        // unknown = world-safe
    CHECK(country_chan("ES", 0) == CC_BLOCKED && country_chan("ES", 37) == CC_BLOCKED && country_chan("ES", 166) == CC_BLOCKED && country_chan("ES", 200) == CC_BLOCKED);
    char o[3];
    CHECK(country_norm("gb", o) == 0 && !strcmp(o, "GB") && country_norm("xx", o) == -1);
    for (const char *c = "DE", *e = "FR"; c; c = c == e ? NULL : e) { CHECK(country_chan(c, 13) == CC_OK && country_chan(c, 120) == CC_DFS); }
    CHECK(country_chan("IT", 165) == CC_OK && country_chan("GB", 56) == CC_DFS);
}

static profile_t mk(const char *ssid, const char *sec, const char *key, int prio, int aj)
{
    profile_t p; memset(&p, 0, sizeof p);
    snprintf(p.ssid, sizeof p.ssid, "%s", ssid); snprintf(p.security, sizeof p.security, "%s", sec); snprintf(p.key, sizeof p.key, "%s", key);
    p.priority = prio; p.autojoin = aj;
    return p;
}

static int vis_all(void *c, const profile_t *p) { (void)c; (void)p; return 1; }
static int vis_not_b(void *c, const profile_t *p) { (void)c; return strcmp(p->ssid, "beta"); }

static void t_profile(void)
{
    profiles_t ps; memset(&ps, 0, sizeof ps);
    const char *why = NULL;
    profile_t a = mk("alpha", "wpa2", "passphrase1", 5, 1), b = mk("beta", "wpa2", "passphrase2", 10, 1), o = mk("cafe", "open", "", 0, 0);
    CHECK(profiles_put(&ps, &a, &why) == 0 && profiles_put(&ps, &b, &why) == 0 && profiles_put(&ps, &o, &why) == 0 && ps.n == 3);
    // invalid
    profile_t bad = mk("", "wpa2", "passphrase1", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == -1 && why);
    bad = mk("x", "wpa2", "short", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == -1);
    bad = mk("x", "open", "key", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == -1);
    bad = mk("x", "wep", "12345", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == 0);
    bad = mk("x2", "wep", "123456", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == -1);
    bad = mk("x3", "rot13", "", 0, 0); CHECK(profiles_put(&ps, &bad, &why) == -1);
    bad = mk("x4", "wpa2", "passphrase1", 5000, 0); CHECK(profiles_put(&ps, &bad, &why) == -1);
    profiles_remove(&ps, "x");
    // replace keeps one entry
    profile_t a2 = mk("alpha", "wpa2", "passphrase9", 1, 0); CHECK(profiles_put(&ps, &a2, &why) == 0 && ps.n == 3 && !strcmp(profiles_find(&ps, "alpha")->key, "passphrase9"));
    CHECK(profiles_put(&ps, &a, &why) == 0);
    // pick: highest priority autojoin
    CHECK(!strcmp(ps.p[profiles_pick(&ps, vis_all, NULL, NULL)].ssid, "beta"));
    CHECK(!strcmp(ps.p[profiles_pick(&ps, vis_not_b, NULL, NULL)].ssid, "alpha"));
    CHECK(!strcmp(ps.p[profiles_pick(&ps, vis_all, NULL, "beta")].ssid, "alpha"));
    CHECK(profiles_pick(&ps, vis_all, NULL, "x") >= 0);       // cafe has autojoin=0 and is never picked
    profiles_remove(&ps, "alpha"); profiles_remove(&ps, "beta");
    CHECK(profiles_pick(&ps, vis_all, NULL, NULL) == -1);
    profiles_put(&ps, &a, &why); profiles_put(&ps, &b, &why);

    // JSON round trip with nasty bytes
    profile_t n = mk("we\"ird \\ ssid\t\x01 caf\xc3\xa9", "wpa2", "pa\"ss\\word,}{[", -7, 1); n.hidden = 1; n.default_route = 1;
    CHECK(profiles_put(&ps, &n, &why) == 0);
    static char js[16384]; static profiles_t back;
    int len = profiles_to_json(&ps, js, sizeof js);
    CHECK(len > 0 && (size_t)len == strlen(js));
    int skipped = -1;
    CHECK(profiles_from_json(js, &back, &skipped) == 0 && skipped == 0 && back.n == ps.n);
    CHECK(back.n == ps.n && !memcmp(&back.p[back.n - 1], &ps.p[ps.n - 1], sizeof(profile_t)));
    CHECK(profiles_find(&back, n.ssid) && profiles_find(&back, n.ssid)->hidden == 1 && profiles_find(&back, n.ssid)->priority == -7 && profiles_find(&back, n.ssid)->default_route == 1);
    CHECK(profiles_to_json(&ps, js, 20) == -1);
    // garbage and tolerance
    CHECK(profiles_from_json("", &back, NULL) == -1 && profiles_from_json("{\"profiles\":[{\"ssid\":}]}", &back, NULL) == -1 && profiles_from_json("[]", &back, NULL) == -1);
    CHECK(profiles_from_json("{\"profiles\":[{\"ssid\":\"a\",\"security\":\"open\",\"extra\":{\"x\":[1,2,\"]\"]},\"future\":1.5e3}],\"other\":null}", &back, &skipped) == 0 && back.n == 1 && skipped == 0);
    CHECK(profiles_from_json("{\"profiles\":[{\"ssid\":\"a\",\"security\":\"wpa2\",\"key\":\"short\"},{\"ssid\":\"b\",\"security\":\"open\"}]}", &back, &skipped) == 0 && back.n == 1 && skipped == 1);
    CHECK(profiles_from_json("{\"profiles\":[]}", &back, NULL) == 0 && back.n == 0);
    CHECK(profiles_from_json("{\"profiles\":[{\"ssid\":\"a\\u0100\"}]}", &back, NULL) == -1);

    // file store: mode 0600, atomic, reload
    char dir[] = "/tmp/awus-ut-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[256]; snprintf(path, sizeof path, "%s/sub/dir/profiles.json", dir);
    static profiles_t st;
    CHECK(profiles_load(path, &st) == 0 && st.n == 0);                   // missing file = empty
    CHECK(profiles_save(path, &ps) == 0);
    struct stat sb;
    CHECK(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0600);
    char d2[300]; snprintf(d2, sizeof d2, "%s/sub/dir", dir);
    CHECK(stat(d2, &sb) == 0 && (sb.st_mode & 0777) == 0700);
    CHECK(profiles_load(path, &st) == 0 && st.n == ps.n && !memcmp(&st.p[0], &ps.p[0], sizeof(profile_t)));
    umask(0);                                                            // a loose umask must not loosen the file
    ps.p[0].priority = 99; CHECK(profiles_save(path, &ps) == 0 && stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0600);
    CHECK(profiles_load(path, &st) == 0 && st.p[0].priority == 99);
    FILE *f = fopen(path, "w"); fputs("{not json", f); fclose(f);
    CHECK(profiles_load(path, &st) == -1);
    char tmp[300]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    CHECK(access(tmp, F_OK) != 0);
    unlink(path); rmdir(d2); snprintf(d2, sizeof d2, "%s/sub", dir); rmdir(d2); rmdir(dir);
}

static void t_proto(void)
{
    proto_req_t q;
    CHECK(proto_parse("status", &q) == 0 && !strcmp(q.cmd, "status") && q.npos == 0 && q.nopt == 0);
    CHECK(proto_parse("rf on", &q) == 0 && !strcmp(q.cmd, "rf") && q.npos == 1 && !strcmp(proto_pos(&q, 0), "on") && proto_pos(&q, 1) == NULL);
    CHECK(proto_parse("join ssid=My%20Net%3Dwork key=p%25w%2B ch=36 hidden=1", &q) == 0 && !strcmp(q.cmd, "join") && q.nopt == 4);
    CHECK(!strcmp(proto_opt(&q, "ssid"), "My Net=work") && !strcmp(proto_opt(&q, "key"), "p%w+") && !strcmp(proto_opt(&q, "ch"), "36") && proto_opt(&q, "bssid") == NULL);
    CHECK(proto_parse("   profile    add   ssid=a  ", &q) == 0 && !strcmp(q.cmd, "profile") && q.npos == 1 && q.nopt == 1);
    CHECK(proto_parse("txpower set 32", &q) == 0 && !strcmp(proto_pos(&q, 1), "32"));
    CHECK(proto_parse("x a=b%3Dc", &q) == 0 && !strcmp(proto_opt(&q, "a"), "b=c"));
    CHECK(proto_parse("x A=1", &q) == 0 && q.nopt == 0 && q.npos == 1);                  // not a key: positional word
    // malformed
    CHECK(proto_parse("", &q) == -1 && proto_parse("   ", &q) == -1 && proto_parse("=x", &q) == -1 && proto_parse("Join", &q) == -1);
    CHECK(proto_parse("x %zz", &q) == -1 && proto_parse("x %4", &q) == -1 && proto_parse("x %", &q) == -1 && proto_parse("x %00", &q) == -1);
    CHECK(proto_parse("x a=%G1", &q) == -1);
    CHECK(proto_parse("x 1 2 3 4 5 6 7", &q) == -1 && proto_parse("x a=1 b=1 c=1 d=1 e=1 f=1 g=1 h=1 i=1 j=1 k=1 l=1 m=1", &q) == -1);
    char big[PROTO_LINE + 8]; memset(big, 'a', sizeof big); big[sizeof big - 1] = 0;
    CHECK(proto_parse(big, &q) == -1);
    char longv[400]; strcpy(longv, "x k="); memset(longv + 4, 'b', 300); longv[304] = 0;
    CHECK(proto_parse(longv, &q) == -1);                                                  // value over PROTO_VAL
    // encode/decode round trip, including every byte value except NUL
    char raw[256], enc[1024], dec[300], line[1100];
    for (int i = 1; i < 256; i++) raw[i - 1] = (char)i;
    raw[255] = 0;
    CHECK(proto_enc(enc, sizeof enc, raw) > 0);
    CHECK(proto_dec(dec, sizeof dec, enc, strlen(enc)) == 255 && !memcmp(dec, raw, 255));
    snprintf(line, sizeof line, "cmd v=%s", enc);
    CHECK(proto_parse(line, &q) == -1);                                                   // 255 raw bytes > PROTO_VAL: refused, not truncated
    char small[64]; for (int i = 1; i < 60; i++) small[i - 1] = (char)i; small[59] = 0;
    char e2[300]; proto_enc(e2, sizeof e2, small); snprintf(line, sizeof line, "cmd v=%s", e2);
    CHECK(proto_parse(line, &q) == 0 && !strcmp(proto_opt(&q, "v"), small));
    CHECK(proto_enc(enc, 5, "abc") == 3 && proto_enc(enc, 3, "abc") == -1 && proto_enc(enc, 4, "a b") == -1 && !strchr(e2, ' ') && !strchr(e2, '='));
    // an SSID that tries to inject a second option or a newline stays one value
    char inj[300]; proto_enc(e2, sizeof e2, "x key=evil\nstatus"); snprintf(inj, sizeof inj, "join ssid=%s", e2);
    CHECK(proto_parse(inj, &q) == 0 && q.nopt == 1 && !strcmp(proto_opt(&q, "ssid"), "x key=evil\nstatus"));
}

static void t_backoff(void)
{
    CHECK(backoff_ms(0) == 1000 && backoff_ms(1) == 2000 && backoff_ms(2) == 4000 && backoff_ms(3) == 8000 && backoff_ms(4) == 16000);
    CHECK(backoff_ms(5) == 30000 && backoff_ms(6) == 30000 && backoff_ms(1000) == 30000 && backoff_ms(-3) == 1000);
    long sum = 0, prev = 0;
    for (int i = 0; i < 12; i++) { long b = backoff_ms(i); CHECK(b >= prev && b <= 30000); prev = b; sum += b; }
    CHECK(sum == 1000 + 2000 + 4000 + 8000 + 16000 + 7 * 30000L);
}

static void t_led(void)
{
    led_t l; led_init(&l);
    CHECK(led_want(&l, 12345) == 0);
    led_set_mode(&l, LED_SOLID, 1000);
    CHECK(led_want(&l, 1000) == 1 && led_want(&l, 99999) == 1);
    led_activity(&l, 2000);
    CHECK(led_want(&l, 2000) == 0 && led_want(&l, 2000 + LED_DIP_MS - 1) == 0 && led_want(&l, 2000 + LED_DIP_MS) == 1);
    led_activity(&l, 2100); CHECK(led_want(&l, 2100) == 1);                                // rate limited
    led_activity(&l, 2000 + LED_DIP_MIN_GAP); CHECK(led_want(&l, 2000 + LED_DIP_MIN_GAP) == 0);
    led_set_mode(&l, LED_SLOW, 5000);
    CHECK(led_want(&l, 5000) == 1 && led_want(&l, 5499) == 1 && led_want(&l, 5500) == 0 && led_want(&l, 5999) == 0 && led_want(&l, 6000) == 1);
    led_activity(&l, 7000); CHECK(led_want(&l, 7000) == 1);                                // dips only while linked
    led_set_mode(&l, LED_FAST, 8000);
    CHECK(led_want(&l, 8000) == 1 && led_want(&l, 8100) == 0 && led_want(&l, 8200) == 1);
    led_set_mode(&l, LED_OFF, 9000);
    CHECK(led_want(&l, 9000) == 0 && led_want(&l, 9100) == 0);
}

int main(void)
{
    t_country(); t_profile(); t_proto(); t_backoff(); t_led();
    printf("test_awusd: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
