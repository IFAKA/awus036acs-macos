# Ad-hoc (IBSS) networks

Status: create + beacon works on the air. Join and the data plane are not built yet.

Use: `awusctl adhoc create --ssid NAME --ch 11 [--key-env VAR]` (daemon running), `awusctl adhoc stop` or `awusctl leave`.
`awusctl adhoc join --ssid NAME --ch N` looks for the IBSS for 6 s and then adopts its BSSID (never run on the air).
Menu app: "Create Ad-hoc Network...". Channels the country rules block, and DFS channels, are refused.

How it works (src/ibss.c): the chip is put in ad-hoc mode (MSR = 1) with a random locally administered MAC and BSSID,
the beacon (SSID, rates, DS channel, IBSS parameter set with ATIM 0, ERP on 2.4 GHz, capability IBSS bit, Privacy bit
for WEP) is written once to the reserved beacon page through the beacon queue, and the chip then sends it every 100 TU
without the host. The host answers probe requests and counts beacon TX flags (`status`: adhoc_beacons_ok).

Checked: `make test-ibss` (frame builder/parser); on the air (ch 11) a macOS CoreWLAN scan lists the IBSS with
beaconInterval 100, and it disappears after `leave`. macOS hides SSID text in scans, so the name itself is not verified.

Not built: data frames over the IBSS (IP, ARP, WEP encryption; the key is stored only), power-save/ATIM, merging two
IBSS with the same SSID, 5 GHz tests.
