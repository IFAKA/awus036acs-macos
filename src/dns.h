// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// dns: DNS servers and search domain for the utun service. The text of the scutil script is built by pure functions
// (unit-tested); dns_apply / dns_remove feed it to /usr/sbin/scutil and need root.
#ifndef DNS_H
#define DNS_H
#include <stddef.h>

// Longest accepted server / domain strings. Servers must be IPv4 dotted quads or IPv6 literals, a domain only
// [A-Za-z0-9.-]: anything else is refused so no text from the network can inject scutil commands.
#define DNS_MAX_SERVERS 6

int dns_valid_server(const char *s);
int dns_valid_domain(const char *s);
// State key of our service: State:/Network/Service/com.awus.<ifname>/DNS. Returns 0, or -1 if ifname is not utunN-like.
int dns_key(char *out, size_t n, const char *ifname);
// scutil script that sets the DNS dictionary for the interface (servers[] may mix IPv4 and IPv6; domain may be NULL or "").
// Returns the script length, or -1 on invalid input or too small a buffer.
int dns_script_set(char *out, size_t n, const char *ifname, const char *const *servers, int nservers, const char *domain);
int dns_script_remove(char *out, size_t n, const char *ifname);
// Run the script through scutil. 0 ok, -1 failed (also when not root).
int dns_apply(const char *ifname, const char *const *servers, int nservers, const char *domain);
int dns_remove(const char *ifname);
#endif
