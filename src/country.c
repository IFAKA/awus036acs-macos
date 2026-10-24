// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <string.h>
#include <ctype.h>
#include "country.h"

typedef struct {
    const char *cc;
    int max24;            // 2.4 GHz channels 1..max24 allowed
    unsigned u5;          // bit i = group i of kGroups allowed (non-DFS and DFS)
} country_t;

// 5 GHz groups: 0 = 36-48, 1 = 52-64 (DFS), 2 = 100-140 (DFS), 3 = 144 (DFS), 4 = 149-165
enum { G_LOW = 1, G_DFS1 = 2, G_DFS2 = 4, G_144 = 8, G_HIGH = 16 };

static const country_t tab[] = {
    { "00", 11, G_LOW },                                                // world-safe: no DFS, no 5.8 GHz, 2.4 GHz 1-11
    { "ES", 13, G_LOW | G_DFS1 | G_DFS2 | G_HIGH },
    { "GB", 13, G_LOW | G_DFS1 | G_DFS2 | G_HIGH },
    { "DE", 13, G_LOW | G_DFS1 | G_DFS2 | G_HIGH },
    { "FR", 13, G_LOW | G_DFS1 | G_DFS2 | G_HIGH },
    { "IT", 13, G_LOW | G_DFS1 | G_DFS2 | G_HIGH },
    { "US", 11, G_LOW | G_DFS1 | G_DFS2 | G_144 | G_HIGH },
    { "JP", 13, G_LOW | G_DFS1 | G_DFS2 },
};
#define NTAB (int)(sizeof tab / sizeof tab[0])

static const country_t *find(const char *cc)
{
    if (!cc || !cc[0] || !cc[1] || cc[2]) return NULL;
    char u[3] = { (char)toupper((unsigned char)cc[0]), (char)toupper((unsigned char)cc[1]), 0 };
    for (int i = 0; i < NTAB; i++) if (!strcmp(tab[i].cc, u)) return &tab[i];
    return NULL;
}

int country_known(const char *cc) { return find(cc) != NULL; }

int country_norm(const char *cc, char out[3])
{
    const country_t *c = find(cc);
    if (!c) return -1;
    out[0] = c->cc[0]; out[1] = c->cc[1]; out[2] = 0;
    return 0;
}

const char *country_list(void) { return "00 ES GB DE FR IT US JP"; }

int country_chan(const char *cc, int ch)
{
    const country_t *c = find(cc);
    if (!c) c = &tab[0];
    if (ch >= 1 && ch <= 14) return ch <= c->max24 ? CC_OK : CC_BLOCKED;
    if (ch >= 36 && ch <= 48 && ch % 4 == 0) return (c->u5 & G_LOW) ? CC_OK : CC_BLOCKED;
    if (ch >= 52 && ch <= 64 && ch % 4 == 0) return (c->u5 & G_DFS1) ? CC_DFS : CC_BLOCKED;
    if (ch >= 100 && ch <= 140 && ch % 4 == 0) return (c->u5 & G_DFS2) ? CC_DFS : CC_BLOCKED;
    if (ch == 144) return (c->u5 & G_144) ? CC_DFS : CC_BLOCKED;
    if (ch >= 149 && ch <= 165 && (ch - 149) % 4 == 0) return (c->u5 & G_HIGH) ? CC_OK : CC_BLOCKED;
    return CC_BLOCKED;
}
