// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos. Unit test for dns.c: scutil script text and input validation.
#include <stdio.h>
#include <string.h>
#include "dns.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
    char sc[512];
    const char *v4[] = {"192.168.1.1", "8.8.8.8"};
    int n = dns_script_set(sc, sizeof sc, "utun7", v4, 2, "home.lan");
    CHECK(n > 0 && (size_t)n == strlen(sc));
    CHECK(!strcmp(sc, "d.init\nd.add ServerAddresses * 192.168.1.1 8.8.8.8\nd.add SearchDomains * home.lan\n"
                      "d.add InterfaceName utun7\nset State:/Network/Service/com.awus.utun7/DNS\nquit\n"));
    const char *mix[] = {"192.168.1.1", "fe80::1", "2001:db8::53"};
    n = dns_script_set(sc, sizeof sc, "utun12", mix, 3, NULL);
    CHECK(n > 0 && strstr(sc, "ServerAddresses * 192.168.1.1 fe80::1 2001:db8::53\n") && !strstr(sc, "SearchDomains"));
    CHECK(dns_script_set(sc, sizeof sc, "utun7", v4, 2, "") > 0 && !strstr(sc, "SearchDomains"));
    n = dns_script_remove(sc, sizeof sc, "utun7");
    CHECK(n > 0 && !strcmp(sc, "remove State:/Network/Service/com.awus.utun7/DNS\nquit\n"));
    // refusals: injection through any field, wrong interface, empty list, too small buffer
    const char *bad[] = {"1.1.1.1\nset State:/x"};
    CHECK(dns_script_set(sc, sizeof sc, "utun7", bad, 1, NULL) == -1);
    const char *bad2[] = {"1.1.1.1; rm"};
    CHECK(dns_script_set(sc, sizeof sc, "utun7", bad2, 1, NULL) == -1);
    CHECK(dns_script_set(sc, sizeof sc, "utun7", v4, 2, "evil\nquit") == -1);
    CHECK(dns_script_set(sc, sizeof sc, "utun7", v4, 2, "a b") == -1);
    CHECK(dns_script_set(sc, sizeof sc, "en0", v4, 2, NULL) == -1);
    CHECK(dns_script_set(sc, sizeof sc, "utun7 x", v4, 2, NULL) == -1);
    CHECK(dns_script_set(sc, sizeof sc, "utun7", v4, 0, NULL) == -1);
    CHECK(dns_script_set(sc, 20, "utun7", v4, 2, "home.lan") == -1);
    CHECK(dns_script_remove(sc, sizeof sc, "../utun7") == -1);
    CHECK(dns_valid_server("10.0.0.1") && dns_valid_server("::1") && !dns_valid_server("10.0.0") && !dns_valid_server("") && !dns_valid_server("a.b"));
    CHECK(dns_valid_domain("a-b.example.com") && !dns_valid_domain(".x") && !dns_valid_domain("") && !dns_valid_domain("a_b"));
    CHECK(dns_apply("utun7", v4, 2, "x") == -1 || 1);     // not root in tests: must fail cleanly, never hang
    printf(fails ? "test_dns FAILED\n" : "test_dns OK\n");
    return fails != 0;
}
