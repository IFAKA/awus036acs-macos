// Classic pcap, linktype 127 (IEEE802_11_RADIOTAP). Radiotap fields: flags, rate (legacy), channel, dBm signal, MCS (HT).
#include <string.h>
#include <sys/time.h>
#include "pcap.h"

int rtl_pcap_open(rtl_pcap_t *p, const char *path)
{
    p->n = 0;
    p->f = fopen(path, "wb");
    if (!p->f) return -1;
    uint8_t h[24] = {0xD4, 0xC3, 0xB2, 0xA1,   // magic 0xa1b2c3d4, little endian on disk
                     2, 0, 4, 0,               // version 2.4
                     0, 0, 0, 0, 0, 0, 0, 0,   // thiszone, sigfigs
                     0xFF, 0xFF, 0, 0,         // snaplen 65535
                     127, 0, 0, 0};            // linktype
    return fwrite(h, 1, sizeof h, p->f) == sizeof h ? 0 : -1;
}

static const uint8_t legacy_500k[12] = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108};

static int chan_freq(int ch)
{
    if (ch >= 1 && ch <= 13) return 2407 + 5 * ch;
    if (ch == 14) return 2484;
    return 5000 + 5 * ch;
}

int rtl_pcap_write(rtl_pcap_t *p, const rtl_frame_t *fr)
{
    if (!p->f) return -1;
    uint8_t rt[32];
    int legacy = fr->rate < 12, ht = fr->rate >= 12 && fr->rate < 28;
    uint32_t present = (1u << 1) | (1u << 3);                 // flags, channel
    if (legacy) present |= 1u << 2;                           // rate
    if (fr->rssi_valid) present |= 1u << 5;                   // dBm antenna signal
    if (ht) present |= 1u << 19;                              // MCS
    memset(rt, 0, sizeof rt);
    int o = 8;
    rt[0] = 0; rt[1] = 0;
    memcpy(rt + 4, &present, 4);
    rt[o++] = fr->has_fcs ? 0x10 : 0;                         // flags: FCS at end
    if (legacy) rt[o++] = legacy_500k[fr->rate];
    if (o & 1) o++;                                           // channel is u16-aligned
    int freq = chan_freq(fr->channel);
    // channel flags: 0x20 CCK, 0x40 OFDM, 0x80 2 GHz, 0x100 5 GHz
    uint16_t cflags = (fr->channel > 14 ? 0x0100 : 0x0080) | (fr->rate < 4 ? 0x0020 : 0x0040);
    rt[o++] = freq & 0xFF; rt[o++] = freq >> 8;
    rt[o++] = cflags & 0xFF; rt[o++] = cflags >> 8;
    if (fr->rssi_valid) rt[o++] = (uint8_t)(int8_t)fr->rssi_dbm;
    if (ht) { rt[o++] = 0x07; rt[o++] = fr->bw ? 1 : 0; rt[o++] = fr->rate - 12; }   // known: bw|mcs|gi
    rt[2] = o; rt[3] = 0;

    struct timeval tv; gettimeofday(&tv, NULL);
    uint32_t hdr[4] = {(uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, (uint32_t)(o + fr->len), (uint32_t)(o + fr->len)};
    if (fwrite(hdr, 1, 16, p->f) != 16 || fwrite(rt, 1, o, p->f) != (size_t)o ||
        fwrite(fr->data, 1, fr->len, p->f) != (size_t)fr->len) return -1;
    p->n++;
    return 0;
}

void rtl_pcap_close(rtl_pcap_t *p)
{
    if (p->f) { fclose(p->f); p->f = NULL; }
}
