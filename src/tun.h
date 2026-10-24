/* tun.h - macOS utun device (PF_SYSTEM / SYSPROTO_CONTROL), IPv4 only.
 * Opening a utun and running tun_configure normally need root. */
#ifndef TUN_H
#define TUN_H
#include <stddef.h>
#include <stdint.h>

/* Open a new non-blocking utun. Writes its name (e.g. "utun7") to ifname.
 * Returns fd, or -1 with errno set (EPERM when unprivileged). */
int tun_open(char ifname[16]);
/* Read one IPv4 packet (4-byte utun header stripped). Returns length, 0 if a
 * non-IPv4 packet was dropped, -1 on error (errno EAGAIN when nothing to read). */
int tun_read(int fd, uint8_t *buf, size_t cap);
/* Write one IPv4 packet (header added). Returns 0 or -1. */
int tun_write(int fd, const uint8_t *ip_pkt, size_t len);
/* Needs root. ifconfig <if> inet <ip> <gw> netmask <mask> up, then a host
 * route to gw via the interface. Never touches the default route.
 * Addresses are dotted-quad strings. 0 ok, -1 error. */
int tun_configure(const char *ifname, const char *ip, const char *gw, const char *mask);
/* Needs root. route -n add -host <ip> -interface <ifname>. 0 ok, -1 error.
 * Refuses 0.0.0.0, "default" and anything that is not a dotted quad. */
int tun_add_host_route(const char *ifname, const char *ip);
#endif
