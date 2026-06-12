#ifndef BLE_SPAM_H
#define BLE_SPAM_H

#include <Arduino.h>
#include <esp_gap_ble_api.h>   // esp_ble_addr_type_t

// ── Spoof device types ────────────────────────────────────────────────────────
typedef enum {
    BLE_DEVICE_AIRPODS_PRO    = 0,
    BLE_DEVICE_AIRPODS_MAX    = 1,
    BLE_DEVICE_AIRPODS_2      = 2,
    BLE_DEVICE_APPLE_WATCH    = 3,
    BLE_DEVICE_FAST_PAIR_BUDS = 4,
    BLE_DEVICE_FAST_PAIR_XM5  = 5,
    BLE_DEVICE_COUNT          = 6
} ble_device_type_t;

extern const char* BLE_DEVICE_NAMES[];

// ── Scanned BLE device ────────────────────────────────────────────────────────
#define BLE_SCAN_MAX 20

typedef struct {
    uint8_t             addr[6];
    char                name[32];
    int8_t              rssi;
    esp_ble_addr_type_t addr_type;  // PUBLIC or RANDOM — needed for directed advertising
} ble_scan_result_t;

extern ble_scan_result_t ble_scan_results[];
extern volatile int      ble_scan_count;
extern volatile bool     ble_scanning;

// ── Init — call once in setup() ───────────────────────────────────────────────
void ble_spam_init();

// ── Spoof mode — impersonate a known device type ──────────────────────────────
void start_ble_spam(ble_device_type_t device);

// ── Target mode — flood a specific scanned device with directed connection requests ──
void start_ble_target(const uint8_t* addr, esp_ble_addr_type_t addr_type);

// ── Scanning ──────────────────────────────────────────────────────────────────
void ble_scan_start();   // start a 5-second BLE scan
void ble_scan_stop();

// ── Stop all BLE activity ─────────────────────────────────────────────────────
void stop_ble_spam();

// ── Call every loop() ─────────────────────────────────────────────────────────
void ble_spam_loop();

extern volatile bool     ble_spam_running;
extern volatile uint32_t ble_packets_sent;

#endif

