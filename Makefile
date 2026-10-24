CC     ?= cc
CFLAGS  = -O2 -Wall $(shell pkg-config --cflags libusb-1.0)
LIBS    = $(shell pkg-config --libs libusb-1.0)

.PHONY: stage2 probe monitor clean
stage2: build/stage2
probe: build/probe
monitor: build/monitor

build:
	mkdir -p build

build/stage2: src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/stage2.c src/rtl.h src/pwrseq8821a.h | build
	$(CC) $(CFLAGS) -o $@ src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/stage2.c $(LIBS)

MON_SRC = src/rtl_usb.c src/rtl_power.c src/rtl_fw.c src/fw8821a.c src/phy.c src/tables.c src/mac.c src/rx.c src/pcap.c src/monitor.c
build/monitor: $(MON_SRC) src/rtl.h src/phy.h src/mac.h src/rx.h src/pcap.h src/pwrseq8821a.h src/tables.h | build
	$(CC) $(CFLAGS) -o $@ $(MON_SRC) $(LIBS)

build/probe: src/probe.c | build
	$(CC) $(CFLAGS) -o $@ src/probe.c $(LIBS)

clean:
	rm -rf build
