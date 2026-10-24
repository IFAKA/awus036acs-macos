// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Stage 2 CLI: open -> power on -> firmware download. Prints one final line.
// Full register log always goes to /tmp/stage2.log; -v also shows it on the terminal.
#include "rtl.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int finish(rtl_t *r, const char *line) {
    puts(line);
    fprintf(stderr, "%s\n", line);
    rtl_close(r);
    return strncmp(line, "STAGE2 OK", 9) ? 1 : 0;
}

int main(int argc, char **argv) {
    int verbose = argc > 1 && !strcmp(argv[1], "-v");
    if (verbose) {
        FILE *tee = popen("tee /tmp/stage2.log >&2", "w");
        if (tee) dup2(fileno(tee), 2);
    } else {
        freopen("/tmp/stage2.log", "w", stderr);
    }
    setvbuf(stderr, NULL, _IOLBF, 0);
    rtl_t r = {0};
    r.verbose = 1;                       // always log registers (to the log file / tee)
    char line[160];
    int e = rtl_open(&r);
    if (e) { snprintf(line, sizeof line, "STAGE2 FAIL open error %d", e); return finish(&r, line); }
    e = rtl_power_on(&r);
    if (e) { snprintf(line, sizeof line, "STAGE2 FAIL power_on error %d (see /tmp/stage2.log)", e); return finish(&r, line); }
    e = rtl_fw_download(&r);
    if (e) { snprintf(line, sizeof line, "STAGE2 FAIL fw_download error %d (see /tmp/stage2.log)", e); return finish(&r, line); }
    snprintf(line, sizeof line, "STAGE2 OK fw_ready=1 cut=%d", r.cut);
    return finish(&r, line);
}
