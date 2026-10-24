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

STA_SRC = $(subst src/inject.c,src/sta.c src/staconn.c,$(INJ_SRC))
build/staconn: $(STA_SRC) src/sta.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(STA_SRC) $(LIBS)
.PHONY: staconn
staconn: build/staconn

.PHONY: test-wpa
test-wpa: build/test_wpa
	./build/test_wpa
build/test_wpa: src/wpa.c src/wpa.h src/test_wpa.c | build
	$(CC) -O2 -Wall -o $@ src/wpa.c src/test_wpa.c

.PHONY: test-net
build/test_net: src/test_net.c src/net.c src/net.h src/tun.c src/tun.h | build
	$(CC) -O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined -o $@ src/test_net.c src/net.c src/tun.c
test-net: build/test_net
	./build/test_net

WIFI_SRC = $(subst src/inject.c,src/sta.c src/wifi.c src/wpa.c src/net.c src/tun.c,$(INJ_SRC))
build/wifi: $(WIFI_SRC) src/tun.h src/sta.h src/wpa.h src/net.h src/rtl.h src/phy.h src/mac.h src/rx.h src/tx.h src/bringup.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(WIFI_SRC) $(LIBS)
.PHONY: wifi
wifi: build/wifi
