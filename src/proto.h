// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// proto: the awusd control protocol (one request line per connection) and the reconnect backoff. Pure, unit-tested.
//
// Request line:   COMMAND [word | key=value]...      (max PROTO_LINE bytes, ends with \n)
//   Every word and every value is percent-encoded: any byte except [A-Za-z0-9._:/,+-] is written as %XX, so spaces, '=',
//   quotes and non-ASCII SSID bytes cannot be confused with the separators. The client (awusctl) does the encoding.
//   A token is "key=value" when it has an '=' after a key of [a-z0-9_] characters; everything else is a positional word.
// Response:       first line "OK" or "ERR <text>", then body lines (key=value for status), then the connection closes.
#ifndef PROTO_H
#define PROTO_H
#include <stddef.h>

#define PROTO_LINE 2048
#define PROTO_MAXPOS 6
#define PROTO_MAXOPT 32
#define PROTO_VAL 200

typedef struct {
    char cmd[24];
    int npos; char pos[PROTO_MAXPOS][PROTO_VAL];
    int nopt; struct { char k[24]; char v[PROTO_VAL]; } opt[PROTO_MAXOPT];
} proto_req_t;

// Parse one request line (without the newline). 0 = ok, -1 = malformed / too long / bad escape / too many tokens.
int proto_parse(const char *line, proto_req_t *rq);
// Value of option key, or NULL. Positional word i, or NULL.
const char *proto_opt(const proto_req_t *rq, const char *key);
const char *proto_pos(const proto_req_t *rq, int i);
// Percent-encode s into out (always NUL terminated). Returns the encoded length, or -1 if cap is too small.
int proto_enc(char *out, size_t cap, const char *s);
// Decode %XX in place into out. Returns the length or -1 on a bad escape / overflow / embedded NUL.
int proto_dec(char *out, size_t cap, const char *s, size_t n);

// Where the daemon listens: /var/run/awusd.sock for root, else $TMPDIR/awusd.sock (or /tmp). Returns 0, -1 if it does not fit.
int proto_sock_path(char *out, size_t cap);
// Reconnect delay in ms after attempt consecutive failures (0 = first retry): 1,2,4,8,16 s, then 30 s forever.
long backoff_ms(int attempt);
#endif
