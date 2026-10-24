// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* tun.c - macOS utun helpers. See tun.h. */
#include "tun.h"
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>

int tun_open(char ifname[16])
{
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    struct ctl_info ci; memset(&ci, 0, sizeof ci);
    strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof ci.ctl_name);
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) goto fail;
    struct sockaddr_ctl sc; memset(&sc, 0, sizeof sc);
    sc.sc_len = sizeof sc; sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL; sc.sc_id = ci.ctl_id; sc.sc_unit = 0; /* 0 = any */
    if (connect(fd, (struct sockaddr *)&sc, sizeof sc) < 0) goto fail;
    socklen_t l = 16;
    char name[16] = {0};
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &l) < 0) goto fail;
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) goto fail;
    memcpy(ifname, name, 16); ifname[15] = 0;
    return fd;
fail: {
        int e = errno; close(fd); errno = e; return -1;
    }
}
#else
int tun_open(char ifname[16]) { (void)ifname; errno = ENOSYS; return -1; }
#endif

#ifndef AF_INET6
#define AF_INET6 30
#endif

int tun_read(int fd, uint8_t *buf, size_t cap)
{
    uint8_t hdr[4];
    struct iovec iov[2] = { { hdr, 4 }, { buf, cap } };
    ssize_t r = readv(fd, iov, 2);
    if (r < 0) return -1;
    if (r < 4) return 0;
    uint32_t af = (uint32_t)hdr[0] << 24 | hdr[1] << 16 | hdr[2] << 8 | hdr[3];
    if (af != 2 /* AF_INET */) return 0;
    return (int)(r - 4);
}

int tun_write(int fd, const uint8_t *ip, size_t len)
{
    if (len < 1) { errno = EINVAL; return -1; }
    uint8_t hdr[4] = {0, 0, 0, (ip[0] >> 4) == 6 ? 30 : 2};
    struct iovec iov[2] = { { hdr, 4 }, { (void *)ip, len } };
    ssize_t w = writev(fd, iov, 2);
    return w == (ssize_t)(len + 4) ? 0 : -1;
}

/* fork/exec without a shell; 0 if the child exits 0. */
static int run(const char *path, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execv(path, argv); _exit(127); }
    int st;
    while (waitpid(pid, &st, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

static int valid_ip(const char *s)
{
    struct in_addr a;
    return s && inet_pton(AF_INET, s, &a) == 1 && a.s_addr != 0;
}
static int valid_if(const char *s)
{
    if (!s || strncmp(s, "utun", 4) || !s[4] || strlen(s) > 15) return 0;
    for (const char *c = s + 4; *c; c++) if (*c < '0' || *c > '9') return 0;
    return 1;
}

int tun_add_host_route(const char *ifname, const char *ip)
{
    if (!valid_if(ifname) || !valid_ip(ip)) { errno = EINVAL; return -1; }
    char *add[]  = { "route", "-n", "add", "-host", (char *)ip, "-interface", (char *)ifname, NULL };
    if (run("/sbin/route", add) == 0) return 0;
    /* route may already exist (ifconfig adds the peer route on point-to-point) */
    char *chg[]  = { "route", "-n", "change", "-host", (char *)ip, "-interface", (char *)ifname, NULL };
    return run("/sbin/route", chg);
}

int tun_configure(const char *ifname, const char *ip, const char *gw, const char *mask)
{
    if (!valid_if(ifname) || !valid_ip(ip) || !valid_ip(gw) || !valid_ip(mask)) {
        errno = EINVAL; return -1;
    }
    char *ifc[] = { "ifconfig", (char *)ifname, "inet", (char *)ip, (char *)gw,
                    "netmask", (char *)mask, "up", NULL };
    if (run("/sbin/ifconfig", ifc) != 0) return -1;
    return tun_add_host_route(ifname, gw);
}
