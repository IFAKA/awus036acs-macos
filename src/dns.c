// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dns.h"

int dns_valid_server(const char *s)
{
    unsigned char b[16];
    if (!s || !*s || strlen(s) > 45) return 0;
    for (const char *p = s; *p; p++) if (!(isxdigit((unsigned char)*p) || *p == '.' || *p == ':')) return 0;
    return inet_pton(AF_INET, s, b) == 1 || inet_pton(AF_INET6, s, b) == 1;
}

int dns_valid_domain(const char *s)
{
    if (!s || !*s || strlen(s) > 63) return 0;
    if (s[0] == '.' || s[0] == '-') return 0;
    for (const char *p = s; *p; p++) if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-')) return 0;
    return 1;
}

int dns_key(char *out, size_t n, const char *ifname)
{
    if (!ifname || strncmp(ifname, "utun", 4) || !ifname[4]) return -1;
    for (const char *p = ifname + 4; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    if (strlen(ifname) > 10) return -1;
    int w = snprintf(out, n, "State:/Network/Service/com.awus.%s/DNS", ifname);
    return w > 0 && (size_t)w < n ? 0 : -1;
}

int dns_script_set(char *out, size_t n, const char *ifname, const char *const *servers, int ns, const char *domain)
{
    char key[96];
    if (dns_key(key, sizeof key, ifname) || ns < 1 || ns > DNS_MAX_SERVERS) return -1;
    size_t o = 0;
    int w = snprintf(out, n, "d.init\nd.add ServerAddresses *");
    if (w < 0 || (size_t)w >= n) return -1;
    o = (size_t)w;
    for (int i = 0; i < ns; i++) {
        if (!dns_valid_server(servers[i])) return -1;
        w = snprintf(out + o, n - o, " %s", servers[i]);
        if (w < 0 || (size_t)w >= n - o) return -1;
        o += (size_t)w;
    }
    if (domain && *domain) {
        if (!dns_valid_domain(domain)) return -1;
        w = snprintf(out + o, n - o, "\nd.add SearchDomains * %s", domain);
        if (w < 0 || (size_t)w >= n - o) return -1;
        o += (size_t)w;
    }
    // scoped to our interface: the interface name pins these servers to the utun, and the key is ours alone
    w = snprintf(out + o, n - o, "\nd.add InterfaceName %s\nset %s\nquit\n", ifname, key);
    if (w < 0 || (size_t)w >= n - o) return -1;
    return (int)(o + (size_t)w);
}

int dns_script_remove(char *out, size_t n, const char *ifname)
{
    char key[96];
    if (dns_key(key, sizeof key, ifname)) return -1;
    int w = snprintf(out, n, "remove %s\nquit\n", key);
    return w > 0 && (size_t)w < n ? w : -1;
}

static int run_scutil(const char *script, int len)
{
    if (geteuid() != 0 || len <= 0) return -1;
    FILE *f = popen("/usr/sbin/scutil >/dev/null 2>&1", "w");
    if (!f) return -1;
    fwrite(script, 1, (size_t)len, f);
    return pclose(f) == 0 ? 0 : -1;
}

int dns_apply(const char *ifname, const char *const *servers, int ns, const char *domain)
{
    char sc[1024];
    return run_scutil(sc, dns_script_set(sc, sizeof sc, ifname, servers, ns, domain));
}

int dns_remove(const char *ifname)
{
    char sc[256];
    return run_scutil(sc, dns_script_remove(sc, sizeof sc, ifname));
}
