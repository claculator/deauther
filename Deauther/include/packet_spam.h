#ifndef PACKET_SPAM_H
#define PACKET_SPAM_H

#include <Arduino.h>

#define MAX_SPAM_TARGETS 16

// Single target
void start_packet_spam(const uint8_t* bssid, uint8_t channel);

// Multi-target (same SSID attack) — bssids[][6], channels[], count
void start_packet_spam_multi(uint8_t bssids[][6], uint8_t* channels, int count);

void stop_packet_spam();
void packet_spam_loop();

extern volatile bool     packet_spam_running;
extern volatile uint32_t packets_sent;
extern volatile uint32_t bytes_sent;
extern volatile uint32_t pkts_auth;
extern volatile uint32_t pkts_assoc;
extern volatile uint32_t pkts_probe;
extern volatile uint32_t pkts_null;
extern volatile uint32_t kbps;

#endif
