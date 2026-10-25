# WPA2-Enterprise (802.1X)

STATUS: integrated and covered by a software loopback test only (`make test-link-eap`). It has NOT been tried on the air:
we have no Enterprise access point or RADIUS server. Treat it as unproven against real equipment.

## Use

    EAPPW=... awusctl join --ssid Corp --sec eap --identity alice --key-env EAPPW --ca /path/ca.pem
    awusctl join --ssid Corp --sec eap --eap-method tls --identity alice --ca ca.pem --cert c.pem --client-key k.pem
    EAPPW=... awusctl profile add --ssid Corp --security eap --identity alice --key-env EAPPW --ca /path/ca.pem

Options: `--eap-method peap|ttls|tls|leap` (default peap), `--eap-inner mschapv2|pap` (PEAP/TTLS, default mschapv2),
`--anon-identity A`, `--server-name N` (required server certificate name), `--insecure-skip-verify` (no server check, unsafe),
`--allow-leap` (LEAP is broken; refused unless given), `--key-pass-env VAR` (password of an encrypted client key).
The password is only read from the environment variable. The app has the same fields in Join Other (802.1X).
Without `--ca` and without `--insecure-skip-verify` a PEAP/TTLS/TLS join is refused (config error), so a server is never trusted by accident.

## Limits

- PEM files only. PKCS#12 (.p12/.pfx) is not supported: convert with `openssl pkcs12 -in x.p12 -nodes -out x.pem` and split the
  certificate and key.
- TLS 1.2 only (Mbed TLS, linked statically). A server that insists on TLS 1.3 will fail.
- Certificate and key files are given as paths; the daemon reads them at join time (so they must stay readable by the daemon).
  The profile file (mode 0600) stores the paths and the password.
- AKM 1 (802.1X) and AKM 5 (802.1X-SHA256, PMF) with CCMP. No SuiteB, no FT, no PMKSA caching (every join runs full EAP).
- A rejected login (wrong password / untrusted server) is reported once and not retried; a timeout is retried.

## Test

`make test-link-eap` runs an in-process fake AP (open auth, association, EAP over EAPOL via the test authenticator in
`src/eap_testauth.h`, then the 4-way, CCMP data, PMF) for PEAP/MSCHAPv2, TTLS/PAP, TTLS/MSCHAPv2 (AKM 5), EAP-TLS and failures.
It needs the `openssl` CLI to make certificates. This is a loopback, not an air test.
