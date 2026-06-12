#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>

#define MAX_DEAUTH_TARGETS 16

void start_deauth(int wifi_number, int attack_type, uint16_t reason);
void start_deauth_multi(int* wifi_numbers, int count, uint16_t reason); // same-SSID targeted
void start_flood_deauth(int wifi_number, uint16_t reason);
void start_flood_deauth_multi(int* wifi_numbers, int count, uint16_t reason);
void stop_deauth();
void deauth_flood_loop();

extern volatile int eliminated_stations;
extern volatile uint32_t deauth_frames_sent;
extern int deauth_type;

#endif
