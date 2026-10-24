CC     ?= cc
CFLAGS  = -O2 -Wall $(shell pkg-config --cflags libusb-1.0)
LIBS    = $(shell pkg-config --libs libusb-1.0)

.PHONY: stage2 probe monitor inject authtest clean
stage2: build/stage2
probe: build/probe
monitor: build/monitor
inject: build/inject
authtest: build/authtest

build:
	mkdir -p build

build/stage2: src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/stage2.c src/rtl.h src/pwrseq8821a.h | build
	$(CC) $(CFLAGS) -o $@ src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/stage2.c $(LIBS)

MON_SRC = src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/phy.c src/tables.c src/mac.c src/rx.c src/tx.c src/pcap.c src/bringup.c src/monitor.c
build/monitor: $(MON_SRC) src/rtl.h src/phy.h src/mac.h src/rx.h src/pcap.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(MON_SRC) $(LIBS)

INJ_SRC = src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/phy.c src/tables.c src/mac.c src/rx.c src/tx.c src/bringup.c src/inject.c
build/inject: $(INJ_SRC) src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(INJ_SRC) $(LIBS)

build/probe: src/probe.c | build
	$(CC) $(CFLAGS) -o $@ src/probe.c $(LIBS)

clean:
	rm -rf build

AUTH_SRC = $(subst src/inject.c,src/authtest.c,$(INJ_SRC))
build/authtest: $(AUTH_SRC) src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(AUTH_SRC) $(LIBS)

INJTEST_SRC = $(subst src/inject.c,src/injtest.c,$(INJ_SRC))
build/injtest: $(INJTEST_SRC) src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(INJTEST_SRC) $(LIBS)
.PHONY: injtest
injtest: build/injtest

STA_SRC = $(subst src/inject.c,src/sta.c src/caps.c src/wep.c src/staconn.c,$(INJ_SRC))
build/staconn: $(STA_SRC) src/sta.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(STA_SRC) $(LIBS)
.PHONY: staconn
staconn: build/staconn

.PHONY: test-wpa
test-wpa: build/test_wpa
	./build/test_wpa
build/test_wpa: src/wpa.c src/wpa.h src/wep.c src/wep.h src/test_wpa.c | build
	$(CC) -O2 -Wall -o $@ src/wpa.c src/wep.c src/test_wpa.c

.PHONY: test-net
build/test_net: src/test_net.c src/net.c src/net.h src/tun.c src/tun.h | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/test_net.c src/net.c src/tun.c
test-net: build/test_net
	./build/test_net

WIFI_SRC = $(subst src/inject.c,src/sta.c src/caps.c src/wep.c src/tkip.c src/link.c src/scanparse.c src/wifi.c src/wpa.c src/net.c src/tun.c,$(INJ_SRC))
build/wifi: $(WIFI_SRC) src/link.h src/tkip.h src/wep.h src/scanparse.h src/tun.h src/sta.h src/wpa.h src/net.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(WIFI_SRC) $(LIBS)
.PHONY: wifi
wifi: build/wifi

.PHONY: test-scanparse test
build/test_scanparse: src/scanparse.c src/scanparse.h src/test_scanparse.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/scanparse.c src/test_scanparse.c
test-scanparse: build/test_scanparse
	./build/test_scanparse
build/test_wep: src/wep.c src/wep.h src/test_wep.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/wep.c src/test_wep.c
.PHONY: test-wep
test-wep: build/test_wep
	./build/test_wep
build/test_tkip: src/tkip.c src/tkip.h src/wep.c src/wep.h src/test_tkip.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/tkip.c src/wep.c src/test_tkip.c
.PHONY: test-tkip
test-tkip: build/test_tkip
	./build/test_tkip
AWUSD_PURE = src/country.c src/profile.c src/proto.c src/led.c src/rtl_usb.c
build/test_awusd: $(AWUSD_PURE) src/country.h src/profile.h src/proto.h src/led.h src/rtl.h src/test_awusd.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined $(shell pkg-config --cflags libusb-1.0) -o $@ $(AWUSD_PURE) src/test_awusd.c $(LIBS)
.PHONY: test-awusd
test-awusd: build/test_awusd
	./build/test_awusd
build/test_caps: src/caps.c src/caps.h src/test_caps.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/caps.c src/test_caps.c
.PHONY: test-caps
test-caps: build/test_caps
	./build/test_caps

build/test_bench: src/benchutil.c src/bench.h src/test_bench.c src/net.c src/net.h src/link.h | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined $(shell pkg-config --cflags libusb-1.0) -o $@ src/benchutil.c src/net.c src/test_bench.c
.PHONY: test-bench
test-bench: build/test_bench
	./build/test_bench
build/test_phy: src/test_phy.c src/phy.c src/mac.c src/tables.c src/rtl.h src/phy.h | build
	$(CC) -O2 -Wall -I src $(shell pkg-config --cflags libusb-1.0) -o $@ src/test_phy.c src/phy.c src/mac.c src/tables.c $(LIBS)
.PHONY: test-phy
test-phy: build/test_phy
	./build/test_phy
test: test-wpa test-net test-scanparse test-wep test-tkip test-awusd test-bench test-phy test-caps

AWUSCTL_SRC = $(subst src/inject.c,src/awusctl.c src/bench.c src/benchutil.c src/scanlib.c src/country.c src/proto.c src/scanparse.c src/sta.c src/caps.c src/wep.c src/tkip.c src/link.c src/wpa.c src/net.c src/tun.c,$(INJ_SRC))
build/awusctl: $(AWUSCTL_SRC) src/bench.h src/scanlib.h src/country.h src/proto.h src/link.h src/sta.h src/wpa.h src/net.h src/tkip.h src/wep.h src/scanparse.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(AWUSCTL_SRC) $(LIBS)
.PHONY: awusctl
awusctl: build/awusctl

AWUSD_SRC = $(subst src/inject.c,src/awusd.c src/scanlib.c src/country.c src/profile.c src/proto.c src/led.c src/scanparse.c src/sta.c src/caps.c src/wep.c src/tkip.c src/link.c src/wpa.c src/net.c src/tun.c,$(INJ_SRC))
AWUSD_HDR = src/link.h src/sta.h src/wpa.h src/net.h src/tkip.h src/wep.h src/scanparse.h src/scanlib.h src/country.h src/profile.h src/proto.h src/led.h src/tun.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h
build/awusd: $(AWUSD_SRC) $(AWUSD_HDR) | build
	$(CC) $(CFLAGS) -o $@ $(AWUSD_SRC) $(LIBS)
.PHONY: awusd
awusd: build/awusd

# Install the daemon under launchd. These targets only PRINT what they would do unless run as root.
PLIST = packaging/com.awus.awusd.plist
.PHONY: install-daemon uninstall-daemon
install-daemon: build/awusd build/awusctl
	@if [ "$$(id -u)" != 0 ]; then echo "would (as root): install -m755 build/awusd /usr/local/libexec/awus/awusd; install -m755 build/awusctl /usr/local/bin/awusctl; mkdir -m700 /var/db/awusd; install -m644 $(PLIST) /Library/LaunchDaemons/; launchctl bootstrap system /Library/LaunchDaemons/com.awus.awusd.plist"; \
	else install -d -m755 /usr/local/libexec/awus /usr/local/bin && install -m755 build/awusd /usr/local/libexec/awus/awusd && install -m755 build/awusctl /usr/local/bin/awusctl && install -d -m700 /var/db/awusd && install -m644 $(PLIST) /Library/LaunchDaemons/ && launchctl bootstrap system /Library/LaunchDaemons/com.awus.awusd.plist; fi
uninstall-daemon:
	@if [ "$$(id -u)" != 0 ]; then echo "would (as root): launchctl bootout system/com.awus.awusd; rm /Library/LaunchDaemons/com.awus.awusd.plist /usr/local/libexec/awus/awusd /usr/local/bin/awusctl (keeps /var/db/awusd profiles)"; \
	else launchctl bootout system/com.awus.awusd; rm -f /Library/LaunchDaemons/com.awus.awusd.plist /usr/local/libexec/awus/awusd /usr/local/bin/awusctl; fi

# ---- menu-bar app and installer (see packaging/) ----
APP_SRC = $(wildcard app/*.swift)
.PHONY: app
app: $(APP_SRC) packaging/Info.plist packaging/build-app.sh
	sh packaging/build-app.sh

# Release binaries for the pkg: libusb linked statically, so the pkg works on a Mac without Homebrew.
LIBUSB_A = $(shell pkg-config --variable=libdir libusb-1.0)/libusb-1.0.a
REL_LIBS = $(LIBUSB_A) -framework IOKit -framework CoreFoundation -framework Security
REL_CFLAGS = -O2 -Wall $(shell pkg-config --cflags libusb-1.0)
build/pkg-bin/awusd: $(AWUSD_SRC) $(AWUSD_HDR)
	mkdir -p build/pkg-bin
	$(CC) $(REL_CFLAGS) -o $@ $(AWUSD_SRC) $(REL_LIBS)
build/pkg-bin/awusctl: $(AWUSCTL_SRC) src/scanlib.h src/country.h src/proto.h
	mkdir -p build/pkg-bin
	$(CC) $(REL_CFLAGS) -o $@ $(AWUSCTL_SRC) $(REL_LIBS)
.PHONY: pkg
pkg: build/pkg-bin/awusd build/pkg-bin/awusctl app
	sh packaging/build-pkg.sh

# ---- WPA3-SAE + PMF engine (pure; no USB): Annex J.10 vectors, RFC 4493, python cross-checks, two-instance exchange ----
build/test_sae: src/sae.c src/sae.h src/wpa3.c src/wpa3.h src/wpa.c src/wpa.h src/wep.c src/test_sae.c | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/sae.c src/wpa3.c src/wpa.c src/wep.c src/test_sae.c
.PHONY: test-sae
test-sae: build/test_sae
	./build/test_sae
test: test-sae
