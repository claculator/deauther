// ─────────────────────────────────────────────────────────────────────────────
//  oled_ui.cpp  —  SSD1306 OLED front-end for ESP32-Deauther
//
//  MENU
//    Scan Networks   → view-only network list (no attack)
//    Deauth Targeted → pick network → reason → sniff-based deauth
//    Deauth Flood    → pick network → reason → broadcast flood deauth
//    Deauth All      → reason → all-channel deauth
//    Packet Spam     → pick network → probe-request flood
//    BLE Spam        → pick BLE device → advertisement spam
//    Stop All        → stop everything, return to menu
//
//  Buttons (INPUT_PULLUP — press = GND):
//    UP     GPIO 14   scroll up   / +1 value
//    DOWN   GPIO 12   scroll down / -1 value
//    SELECT GPIO 13   confirm / execute
// ─────────────────────────────────────────────────────────────────────────────

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include "oled_ui.h"
#include "definitions.h"
#include "deauth.h"
#include "packet_spam.h"
#include "ble_spam.h"

// ── Display ───────────────────────────────────────────────────────────────────
static Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// ── States ────────────────────────────────────────────────────────────────────
enum UIState {
    S_MAIN_MENU,

    // Scan Networks (view only)
    S_SCAN_LIST,
    S_SCAN_DETAIL,

    // Deauth Targeted
    S_DTARGET_LIST,
    S_DTARGET_REASON,
    S_DTARGET_RUNNING,

    // Deauth Flood
    S_DFLOOD_LIST,
    S_DFLOOD_REASON,
    S_DFLOOD_RUNNING,

    // Deauth All
    S_DALL_REASON,
    S_DALL_RUNNING,

    // Packet Spam
    S_PSPAM_LIST,
    S_PSPAM_RUNNING,

    // BLE Spam
    S_BLE_LIST,
    S_BLE_RUNNING,
    S_BLE_SCAN_SCANNING,  // scanning for nearby devices
    S_BLE_SCAN_LIST,      // pick a real device to target
    S_BLE_TARGET_RUNNING, // flooding a specific BLE device
};

// ── State variables ───────────────────────────────────────────────────────────
static UIState  ui_state      = S_MAIN_MENU;
static int      selected_item = 0;
static int      scroll_offset = 0;
static int      num_networks  = 0;
static uint16_t reason        = 1;
static int      net_target    = -1;
static int      ble_selected  = 0;
static bool     multi_ssid    = false;  // when true, attacks hit ALL APs with same SSID

// ── Menu ──────────────────────────────────────────────────────────────────────
// multi_ssid flag shown in menu dynamically (see render_main_menu)
static const char* MENU_ITEMS[] = {
    "Scan Networks",
    "Deauth Targeted",
    "Deauth Flood",
    "Deauth All",
    "Packet Spam",
    "BLE Spam",
    "Multi-SSID: OFF",   // index 6 — label updated at render time
    "Stop All"
};
static const int MENU_COUNT = 8;

// ── Display presence ──────────────────────────────────────────────────────────
static bool display_present = false;

// ── View mode (used during all running attack states) ─────────────────────────
enum ViewMode { VIEW_BASIC = 0, VIEW_ADVANCED = 1, VIEW_GRAPH = 2 };
static ViewMode view_mode = VIEW_BASIC;

// ── Graph ring buffer — 1 sample/sec, 64 samples ─────────────────────────────
#define GRAPH_SAMPLES 64
static uint32_t graph_pps[GRAPH_SAMPLES] = {0};  // packets per second
static uint32_t graph_bps[GRAPH_SAMPLES] = {0};  // bytes per second
static int      graph_head   = 0;
static uint32_t graph_last_pkts = 0;
static uint32_t graph_last_bytes = 0;

static void graph_push_sample() {
    // Called every second from the refresh timer
    uint32_t cur_pkts  = packets_sent + (uint32_t)eliminated_stations + (uint32_t)ble_packets_sent;
    uint32_t cur_bytes = bytes_sent;
    graph_pps[graph_head]  = cur_pkts  - graph_last_pkts;
    graph_bps[graph_head]  = cur_bytes - graph_last_bytes;
    graph_last_pkts  = cur_pkts;
    graph_last_bytes = cur_bytes;
    graph_head = (graph_head + 1) % GRAPH_SAMPLES;
}

static void graph_reset() {
    memset(graph_pps,  0, sizeof(graph_pps));
    memset(graph_bps,  0, sizeof(graph_bps));
    graph_head = 0;
    graph_last_pkts  = 0;
    graph_last_bytes = 0;
}

// ── Headless serial output helpers ────────────────────────────────────────────
// Returns true when one of the running attack states is active
static bool is_running_state() {
    return ui_state == S_DTARGET_RUNNING || ui_state == S_DFLOOD_RUNNING  ||
           ui_state == S_DALL_RUNNING    || ui_state == S_PSPAM_RUNNING   ||
           ui_state == S_BLE_RUNNING     || ui_state == S_BLE_TARGET_RUNNING;
}
#define HDR_H      10
#define FTR_H       8
#define LIST_Y     (HDR_H + 2)
#define LIST_BOT   (SCREEN_HEIGHT - FTR_H - 1)
#define LINE_H     11
#define LINES_VIS  ((LIST_BOT - LIST_Y) / LINE_H)

// ── Button debounce ───────────────────────────────────────────────────────────
static unsigned long last_btn_ms[3] = {0, 0, 0};
static bool          btn_held[3]    = {false, false, false};

// ═════════════════════════════════════════════════════════════════════════════
//  Drawing primitives
// ═════════════════════════════════════════════════════════════════════════════

static void draw_header(const char* title) {
    display.fillRect(0, 0, SCREEN_WIDTH, HDR_H, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK);
    display.setTextSize(1);
    display.setCursor(2, 2);
    display.print(title);
    display.setTextColor(SSD1306_WHITE);
}

static void draw_footer(const char* left, const char* mid, const char* right) {
    int y = SCREEN_HEIGHT - FTR_H;
    display.fillRect(0, y, SCREEN_WIDTH, FTR_H, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK);
    display.setTextSize(1);
    if (left  && left[0])  { display.setCursor(1, y + 1); display.print(left); }
    if (mid   && mid[0])   { int w = strlen(mid) * 6;  display.setCursor((SCREEN_WIDTH - w) / 2, y + 1); display.print(mid); }
    if (right && right[0]) { int w = strlen(right) * 6; display.setCursor(SCREEN_WIDTH - w - 1, y + 1); display.print(right); }
    display.setTextColor(SSD1306_WHITE);
}

static void draw_row(int row_idx, const char* label, bool highlighted) {
    int y = LIST_Y + row_idx * LINE_H;
    if (y + LINE_H > LIST_BOT) return;  // guard — never draw below footer
    if (highlighted) {
        display.fillRect(0, y, SCREEN_WIDTH - 4, LINE_H - 1, SSD1306_WHITE);
        display.setTextColor(SSD1306_BLACK);
    } else {
        display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.print(label);
    display.setTextColor(SSD1306_WHITE);
}

static void draw_scrollbar(int total) {
    if (total <= LINES_VIS) return;
    int track_h = LIST_BOT - LIST_Y;
    int bar_h   = max(3, track_h * LINES_VIS / total);
    int bar_y   = LIST_Y + (track_h - bar_h) * scroll_offset / max(1, total - LINES_VIS);
    display.drawRect(SCREEN_WIDTH - 3, LIST_Y, 3, track_h, SSD1306_WHITE);
    display.fillRect(SCREEN_WIDTH - 3, bar_y,  3, bar_h,   SSD1306_WHITE);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

static void navigate(int* sel, int* offset, int delta, int total) {
    *sel += delta;
    if (*sel < 0)       *sel = 0;
    if (*sel >= total)  *sel = total - 1;
    if (*sel < *offset)               *offset = *sel;
    if (*sel >= *offset + LINES_VIS)  *offset  = *sel - LINES_VIS + 1;
}

static void reset_list() {
    selected_item = 0;
    scroll_offset = 0;
}

// Collect all scan indices whose SSID matches network ni
// Returns count, fills out_indices[] (max MAX_DEAUTH_TARGETS entries)
static int collect_same_ssid(int ni, int* out_indices) {
    String target_ssid = WiFi.SSID(ni);
    int count = 0;
    for (int i = 0; i < num_networks && count < MAX_DEAUTH_TARGETS; i++) {
        if (WiFi.SSID(i) == target_ssid) {
            out_indices[count++] = i;
        }
    }
    return count;
}

static void go_main_menu() {
    reset_list();
    ui_state = S_MAIN_MENU;
}

// Show scanning splash, run WiFi.scanNetworks(), reset list cursor
static void do_scan() {
    display.clearDisplay();
    draw_header("Scanning...");
    display.setTextSize(1);
    display.setCursor(14, 26); display.print("Scanning for WiFi");
    display.setCursor(30, 38); display.print("networks...");
    display.display();
    num_networks = WiFi.scanNetworks();
    reset_list();
}

// ═════════════════════════════════════════════════════════════════════════════
//  Screen renderers
// ═════════════════════════════════════════════════════════════════════════════

static void render_main_menu() {
    display.clearDisplay();
    draw_header("ESP32 Deauther");
    for (int row = 0; row < LINES_VIS; row++) {
        int idx = scroll_offset + row;
        if (idx >= MENU_COUNT) break;
        char label[22];
        if (idx == 6)
            snprintf(label, sizeof(label), "Multi-SSID: %s", multi_ssid ? "ON " : "OFF");
        else
            snprintf(label, sizeof(label), "%.21s", MENU_ITEMS[idx]);
        draw_row(row, label, idx == selected_item);
    }
    draw_scrollbar(MENU_COUNT);
    draw_footer("^", "SELECT", "v");
    display.display();
}

// Generic scrollable network list with "< Back" at index 0
static void render_net_list(const char* title) {
    display.clearDisplay();
    draw_header(title);
    int total = num_networks + 1;
    for (int row = 0; row < LINES_VIS; row++) {
        int idx = scroll_offset + row;
        if (idx >= total) break;
        char label[22];
        if (idx == 0) {
            snprintf(label, sizeof(label), "< Back");
        } else {
            int ni = idx - 1;
            String ssid = WiFi.SSID(ni);
            if (ssid.length() == 0) ssid = "(hidden)";
            uint8_t* b = WiFi.BSSID(ni);
            // Append last 2 BSSID bytes so duplicate SSIDs are distinguishable
            // e.g.  "MyNetwork [A1:B2]"
            char ssid_trunc[13];
            snprintf(ssid_trunc, sizeof(ssid_trunc), "%.12s", ssid.c_str());
            snprintf(label, sizeof(label), "%s [%02X:%02X]",
                     ssid_trunc, b[4], b[5]);
        }
        draw_row(row, label, idx == selected_item);
    }
    draw_scrollbar(total);
    draw_footer("^", "SELECT", "v");
    display.display();
}

static void render_scan_detail(int ni) {
    display.clearDisplay();
    draw_header("Network Info");
    char buf[24];
    display.setTextSize(1);

    String ssid = WiFi.SSID(ni);
    if (ssid.length() == 0) ssid = "(hidden)";
    snprintf(buf, sizeof(buf), "%.21s", ssid.c_str());
    display.setCursor(2, 13); display.print(buf);
    display.setCursor(2, 23); display.print(WiFi.BSSIDstr(ni));

    snprintf(buf, sizeof(buf), "CH:%d  RSSI:%ddBm", WiFi.channel(ni), WiFi.RSSI(ni));
    display.setCursor(2, 33); display.print(buf);

    const char* enc = "Open";
    switch (WiFi.encryptionType(ni)) {
        case WIFI_AUTH_WEP:             enc = "WEP";       break;
        case WIFI_AUTH_WPA_PSK:         enc = "WPA";       break;
        case WIFI_AUTH_WPA2_PSK:        enc = "WPA2";      break;
        case WIFI_AUTH_WPA_WPA2_PSK:    enc = "WPA/WPA2";  break;
        case WIFI_AUTH_WPA2_ENTERPRISE: enc = "WPA2-Ent";  break;
        default: break;
    }
    snprintf(buf, sizeof(buf), "Enc: %s", enc);
    display.setCursor(2, 43); display.print(buf);

    draw_footer("", "BACK", "");
    display.display();
}

static void render_reason_picker(const char* context) {
    display.clearDisplay();
    draw_header(context);
    display.setTextSize(1);
    display.setCursor(2, 13);
    display.print("Reason code:");

    display.setTextSize(3);
    char rstr[4];
    snprintf(rstr, sizeof(rstr), "%d", reason);
    int w = strlen(rstr) * 18;
    display.setCursor((SCREEN_WIDTH - w) / 2, 22);
    display.print(rstr);
    display.setTextSize(1);

    static const char* reasons[] = {
        "", "Unspecified", "Auth invalid", "Leaving IBSS",
        "Inactivity", "AP overloaded", "Class2 unauth", "Class3 unassoc",
        "Leaving BSS", "(Re)assoc unauth", "Power cap", "Supp CH bad",
        "BSS transition", "Bad element", "MIC fail", "4-Way timeout",
        "Group key timeout", "4-Way mismatch", "Bad grp cipher",
        "Bad pair cipher", "Bad AKMP", "Bad RSNE ver",
        "Bad RSNE cap", "802.1X fail", "Cipher rejected"
    };
    if (reason <= 24) { display.setCursor(2, 47); display.print(reasons[reason]); }
    draw_footer("^ +1", "FIRE!", "v -1");
    display.display();
}

// Generic live attack screen with flashing header
// ─────────────────────────────────────────────────────────────────────────────
//  Graph & headless serial renderers
// ─────────────────────────────────────────────────────────────────────────────

// Render an ASCII sparkline on Serial — 32 chars wide, uses _▂▄▆█
static void serial_graph(const uint32_t* buf, const char* label) {
    // Find max for scaling
    uint32_t mx = 1;
    for (int i = 0; i < GRAPH_SAMPLES; i++) if (buf[i] > mx) mx = buf[i];

    Serial.printf("  %s (max %lu)\r\n  |", label, (unsigned long)mx);
    // Print last 32 samples
    int start = (graph_head - 32 + GRAPH_SAMPLES) % GRAPH_SAMPLES;
    const char* bars = " .:+|#";
    for (int i = 0; i < 32; i++) {
        int idx = (start + i) % GRAPH_SAMPLES;
        int level = (int)(buf[idx] * 5 / mx);
        Serial.print(bars[level]);
    }
    Serial.println("|");
}

// Draw a pixel bar chart on the OLED — fills bottom GRAPH_H rows
#define GRAPH_H  18
static void oled_graph(const uint32_t* buf, const char* label) {
    // Area: x 0..127, y LIST_Y .. LIST_Y+GRAPH_H
    int gx = 0, gy = LIST_Y, gw = SCREEN_WIDTH, gh = GRAPH_H;
    display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
    display.setCursor(2, gy); display.print(label);
    gy += 9;
    gh -= 9;

    // Find max
    uint32_t mx = 1;
    for (int i = 0; i < GRAPH_SAMPLES; i++) if (buf[i] > mx) mx = buf[i];

    // Draw 64 bars across full width (2px each)
    int start = graph_head;  // oldest sample
    for (int i = 0; i < GRAPH_SAMPLES; i++) {
        int idx = (start + i) % GRAPH_SAMPLES;
        int bar = (int)((uint64_t)buf[idx] * gh / mx);
        if (bar < 1 && buf[idx] > 0) bar = 1;
        int bx = gx + i * gw / GRAPH_SAMPLES;
        int bw = max(1, gw / GRAPH_SAMPLES);
        display.fillRect(bx, gy + gh - bar, bw, bar, SSD1306_WHITE);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Headless (no OLED) serial renderer — called from refresh loop
// ─────────────────────────────────────────────────────────────────────────────
static const char* VIEW_NAMES[] = { "BASIC", "ADVANCED", "GRAPH" };

static void headless_render() {
    // Clear terminal line with CR
    Serial.print("\033[2J\033[H");  // ANSI clear screen

    // Attack name + view mode
    const char* atk = "IDLE";
    switch (ui_state) {
        case S_DTARGET_RUNNING:    atk = "DEAUTH TARGETED"; break;
        case S_DFLOOD_RUNNING:     atk = "DEAUTH FLOOD";    break;
        case S_DALL_RUNNING:       atk = "DEAUTH ALL";      break;
        case S_PSPAM_RUNNING:      atk = "DOS ATTACK";      break;
        case S_BLE_RUNNING:        atk = "BLE SPOOF";       break;
        case S_BLE_TARGET_RUNNING: atk = "BLE TARGET";      break;
        default: break;
    }
    Serial.printf("=== %s | [%s] ===\r\n", atk, VIEW_NAMES[(int)view_mode]);
    Serial.println("  UP/DOWN: change view  |  SELECT: stop");
    Serial.println();

    if (view_mode == VIEW_BASIC) {
        // ── Basic ─────────────────────────────────────────────────────────────
        if (ui_state == S_PSPAM_RUNNING) {
            uint32_t kb = bytes_sent / 1024;
            Serial.printf("  Packets : %lu\r\n",   (unsigned long)packets_sent);
            Serial.printf("  Data    : %lu kB\r\n", (unsigned long)kb);
            Serial.printf("  Rate    : %lu kB/s\r\n",(unsigned long)kbps);
        } else if (ui_state == S_BLE_RUNNING || ui_state == S_BLE_TARGET_RUNNING) {
            Serial.printf("  Adverts : %lu\r\n", (unsigned long)ble_packets_sent);
        } else {
            Serial.printf("  Eliminated : %d\r\n", (int)eliminated_stations);
            Serial.printf("  Frames     : %lu\r\n", (unsigned long)deauth_frames_sent);
        }
        if (net_target >= 0 && (ui_state != S_BLE_RUNNING && ui_state != S_BLE_TARGET_RUNNING)) {
            Serial.printf("  SSID    : %s\r\n", WiFi.SSID(net_target).c_str());
            Serial.printf("  Channel : %d\r\n", WiFi.channel(net_target));
        }
        Serial.printf("  Multi   : %s\r\n", multi_ssid ? "ON" : "OFF");

    } else if (view_mode == VIEW_ADVANCED) {
        // ── Advanced ──────────────────────────────────────────────────────────
        if (ui_state == S_PSPAM_RUNNING) {
            Serial.printf("  Total pkts  : %lu\r\n",   (unsigned long)packets_sent);
            Serial.printf("  Total bytes : %lu kB\r\n",(unsigned long)(bytes_sent/1024));
            Serial.printf("  Rate        : %lu kB/s\r\n",(unsigned long)kbps);
            Serial.printf("  AUTH frames : %lu\r\n",   (unsigned long)pkts_auth);
            Serial.printf("  ASSOC frames: %lu\r\n",   (unsigned long)pkts_assoc);
            Serial.printf("  PROBE frames: %lu\r\n",   (unsigned long)pkts_probe);
            Serial.printf("  NULL frames : %lu\r\n",   (unsigned long)pkts_null);
        } else if (ui_state == S_BLE_RUNNING || ui_state == S_BLE_TARGET_RUNNING) {
            Serial.printf("  Adverts sent: %lu\r\n",   (unsigned long)ble_packets_sent);
            if (ui_state == S_BLE_TARGET_RUNNING) {
                Serial.printf("  Target MAC  : %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                    ble_scan_results[max(0, ble_selected-1)].addr[0],
                    ble_scan_results[max(0, ble_selected-1)].addr[1],
                    ble_scan_results[max(0, ble_selected-1)].addr[2],
                    ble_scan_results[max(0, ble_selected-1)].addr[3],
                    ble_scan_results[max(0, ble_selected-1)].addr[4],
                    ble_scan_results[max(0, ble_selected-1)].addr[5]);
            }
        } else {
            Serial.printf("  Eliminated  : %d\r\n",    (int)eliminated_stations);
            Serial.printf("  Frames sent : %lu\r\n",   (unsigned long)deauth_frames_sent);
            Serial.printf("  Reason code : %d\r\n",    (int)reason);
            if (net_target >= 0) {
                uint8_t* b = WiFi.BSSID(net_target);
                if (b) Serial.printf("  BSSID : %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                                     b[0],b[1],b[2],b[3],b[4],b[5]);
                Serial.printf("  SSID  : %s  CH:%d\r\n",
                              WiFi.SSID(net_target).c_str(),
                              WiFi.channel(net_target));
            }
            Serial.printf("  Multi-SSID  : %s\r\n", multi_ssid ? "ON" : "OFF");
        }
    } else {
        // ── Graph ─────────────────────────────────────────────────────────────
        Serial.println("  -- Packets/sec --");
        serial_graph(graph_pps, "pkt/s");
        Serial.println();
        if (ui_state == S_PSPAM_RUNNING) {
            Serial.println("  -- Bytes/sec --");
            serial_graph(graph_bps, "B/s");
        }
    }
}

static void render_live(const char* hdr, const char* l1, const char* l2,
                         const char* l3, const char* l4, bool can_stop) {
    if (!display_present) return;  // headless handled separately
    display.clearDisplay();
    static bool flash = false;
    flash = !flash;

    if (view_mode == VIEW_GRAPH) {
        // ── Graph view ────────────────────────────────────────────────────────
        // Header row (no flash — fixed so user can read)
        display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
        display.setCursor(2, 2); display.print(hdr);
        // Small view label top-right
        display.setCursor(90, 2);
        display.print("[GRAPH]");
        // Graph fills body
        const uint32_t* buf = (ui_state == S_PSPAM_RUNNING) ? graph_bps : graph_pps;
        const char* glabel  = (ui_state == S_PSPAM_RUNNING) ? "B/s" : "pkt/s";
        oled_graph(buf, glabel);
        draw_footer("^view", can_stop ? "STOP" : "RST", "view v");
        display.display();
        return;
    }

    // ── Basic or Advanced view ────────────────────────────────────────────────
    if (flash) draw_header(hdr);
    else {
        display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
        display.setCursor(2, 2); display.print(hdr);
    }

    // View mode indicator top-right (tiny)
    display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
    const char* vl = (view_mode == VIEW_ADVANCED) ? "[ADV]" : "[BSC]";
    display.setCursor(SCREEN_WIDTH - strlen(vl)*6 - 1, 2);
    display.print(vl);

    display.setTextSize(1); display.setTextColor(SSD1306_WHITE);

    if (view_mode == VIEW_BASIC) {
        if (l1) { display.setCursor(2, 13); display.print(l1); }
        if (l2) { display.setCursor(2, 23); display.print(l2); }
        if (l3) { display.setCursor(2, 33); display.print(l3); }
        if (l4) { display.setCursor(2, 43); display.print(l4); }
    } else {
        // Advanced: always show packet+byte stats regardless of which screen
        char av1[22], av2[22], av3[22], av4[22];
        if (ui_state == S_PSPAM_RUNNING) {
            snprintf(av1, 22, "AUTH:%lu ASC:%lu",  (unsigned long)pkts_auth,  (unsigned long)pkts_assoc);
            snprintf(av2, 22, "PRB:%lu NUL:%lu",   (unsigned long)pkts_probe, (unsigned long)pkts_null);
            snprintf(av3, 22, "%lu kB  %lu kB/s",  (unsigned long)(bytes_sent/1024), (unsigned long)kbps);
            snprintf(av4, 22, "Pkts: %lu",         (unsigned long)packets_sent);
        } else {
            snprintf(av1, 22, "Elim: %d",          (int)eliminated_stations);
            snprintf(av2, 22, "Frames: %lu",        (unsigned long)deauth_frames_sent);
            snprintf(av3, 22, "Reason: %d",         (int)reason);
            snprintf(av4, 22, "Multi: %s",          multi_ssid ? "ON" : "OFF");
        }
        display.setCursor(2, 13); display.print(av1);
        display.setCursor(2, 23); display.print(av2);
        display.setCursor(2, 33); display.print(av3);
        display.setCursor(2, 43); display.print(av4);
    }

    draw_footer("^view", can_stop ? "STOP" : "RST", "view v");
    display.display();
}

static void render_dtarget_running() {
    char l1[22], l2[22], l3[22];
    String ssid = WiFi.SSID(net_target);
    if (ssid.length() == 0) ssid = "(hidden)";
    snprintf(l1, sizeof(l1), "%.21s", ssid.c_str());
    snprintf(l2, sizeof(l2), "CH:%d R:%d%s", WiFi.channel(net_target), reason,
             multi_ssid ? " ALL-AP" : "");
    snprintf(l3, sizeof(l3), "Elim:%d Frm:%lu", eliminated_stations,
             (unsigned long)deauth_frames_sent);
    render_live("!! TARGETED !!", l1, l2, l3, "Waits for traffic", true);
}

static void render_dflood_running() {
    char l1[22], l2[22], l3[22];
    String ssid = WiFi.SSID(net_target);
    if (ssid.length() == 0) ssid = "(hidden)";
    snprintf(l1, sizeof(l1), "%.21s", ssid.c_str());
    snprintf(l2, sizeof(l2), "CH:%d R:%d%s", WiFi.channel(net_target), reason,
             multi_ssid ? " ALL-AP" : "");
    snprintf(l3, sizeof(l3), "Frames: %lu", (unsigned long)deauth_frames_sent);
    render_live("!! FLOOD !!", l1, l2, l3, "Broadcast->all", true);
}

static void render_dall_running() {
    char l2[22], l3[22], l4[22];
    snprintf(l2, sizeof(l2), "Reason: %d", reason);
    snprintf(l3, sizeof(l3), "Eliminated: %d", eliminated_stations);
    snprintf(l4, sizeof(l4), "Frames: %lu", (unsigned long)deauth_frames_sent);
    render_live("!! DEAUTH ALL !!", "All channels", l2, l3, l4, true);
}

static void render_pspam_running() {
    // Full stats — show kB/s, total KB, per-type breakdown on alternating frames
    static bool toggle = false;
    toggle = !toggle;

    char hdr[22];
    String ssid = WiFi.SSID(net_target);
    if (ssid.length() == 0) ssid = "(hidden)";
    snprintf(hdr, sizeof(hdr), "%.21s", ssid.c_str());

    display.clearDisplay();
    static bool flash = false; flash = !flash;
    if (flash) draw_header(">> DoS ATTACK <<");
    else {
        display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
        display.setCursor(2, 2); display.print(">> DoS ATTACK <<");
    }
    display.setTextSize(1); display.setTextColor(SSD1306_WHITE);

    display.setCursor(2, 13); display.print(hdr);

    char l2[22], l3[22], l4[22];
    if (toggle) {
        // Page 1: throughput
        uint32_t total_kb = bytes_sent / 1024;
        snprintf(l2, sizeof(l2), "%lu kB/s  %lu kB tot", (unsigned long)kbps, (unsigned long)total_kb);
        snprintf(l3, sizeof(l3), "%lu pkts", (unsigned long)packets_sent);
        snprintf(l4, sizeof(l4), "CH:%d%s", WiFi.channel(net_target),
                 multi_ssid ? " MULTI" : "");
    } else {
        // Page 2: per-type breakdown
        snprintf(l2, sizeof(l2), "AUTH:%lu ASC:%lu", (unsigned long)pkts_auth, (unsigned long)pkts_assoc);
        snprintf(l3, sizeof(l3), "PRB:%lu NUL:%lu", (unsigned long)pkts_probe, (unsigned long)pkts_null);
        snprintf(l4, sizeof(l4), "%lu kB sent", (unsigned long)(bytes_sent / 1024));
    }
    display.setCursor(2, 23); display.print(l2);
    display.setCursor(2, 33); display.print(l3);
    display.setCursor(2, 43); display.print(l4);
    draw_footer("", "STOP", "");
    display.display();
}

static void render_ble_list() {
    display.clearDisplay();
    draw_header("BLE Spam");
    // First row: "Scan Devices" option, then spoof presets
    int total = BLE_DEVICE_COUNT + 1;  // +1 for "Scan & Target" at top
    for (int row = 0; row < LINES_VIS; row++) {
        int idx = scroll_offset + row;
        if (idx >= total) break;
        char label[22];
        if (idx == 0)
            snprintf(label, sizeof(label), "> Scan & Target");
        else
            snprintf(label, sizeof(label), "%.21s", BLE_DEVICE_NAMES[idx - 1]);
        draw_row(row, label, idx == ble_selected);
    }
    draw_scrollbar(total);
    draw_footer("^", "SELECT", "v");
    display.display();
}

static void render_ble_scan_list() {
    display.clearDisplay();
    draw_header("BLE Devices");
    int total = ble_scan_count + 1;  // +1 for < Back
    for (int row = 0; row < LINES_VIS; row++) {
        int idx = scroll_offset + row;
        if (idx >= total) break;
        char label[22];
        if (idx == 0) {
            snprintf(label, sizeof(label), "< Back");
        } else {
            const ble_scan_result_t& r = ble_scan_results[idx - 1];
            snprintf(label, sizeof(label), "%.14s %ddBm", r.name, r.rssi);
        }
        draw_row(row, label, idx == ble_selected);
    }
    draw_scrollbar(total);
    draw_footer("^", "SELECT", "v");
    display.display();
}

static void render_ble_target_running() {
    // Which device are we targeting?
    int ti = ble_selected - 1;  // index into ble_scan_results
    char l1[22], l2[22], l3[22];
    if (ti >= 0 && ti < ble_scan_count) {
        snprintf(l1, sizeof(l1), "%.21s", ble_scan_results[ti].name);
        snprintf(l2, sizeof(l2), "%02X:%02X:%02X %02X:%02X:%02X",
                 ble_scan_results[ti].addr[0], ble_scan_results[ti].addr[1],
                 ble_scan_results[ti].addr[2], ble_scan_results[ti].addr[3],
                 ble_scan_results[ti].addr[4], ble_scan_results[ti].addr[5]);
    } else {
        snprintf(l1, sizeof(l1), "Unknown device");
        snprintf(l2, sizeof(l2), "");
    }
    snprintf(l3, sizeof(l3), "Reqs: %lu", (unsigned long)ble_packets_sent);
    render_live(">> BLE TARGET <<", l1, l2, l3, "Conn req flood", true);
}

static void render_ble_running() {
    char l2[22], l3[22];
    int di = ble_selected - 1;
    if (di < 0) di = 0;
    snprintf(l2, sizeof(l2), "%.21s", BLE_DEVICE_NAMES[di]);
    snprintf(l3, sizeof(l3), "Adverts: %lu", (unsigned long)ble_packets_sent);
    render_live(">> BLE SPAM <<", "Spoofing:", l2, l3, "Rand MAC/burst", true);
}

// ── Coordinated Attack screens ────────────────────────────────────────────────

// ═════════════════════════════════════════════════════════════════════════════
//  Button handler
// ═════════════════════════════════════════════════════════════════════════════

// Cycle view mode: UP=prev, DOWN=next, wraps around
static void cycle_view(int dir) {
    view_mode = (ViewMode)(((int)view_mode + dir + 3) % 3);
}

static void handle_button(int btn) {
    switch (ui_state) {

    // ── Main menu ─────────────────────────────────────────────────────────────
    case S_MAIN_MENU:
        if (btn == 0) navigate(&selected_item, &scroll_offset, -1, MENU_COUNT);
        if (btn == 1) navigate(&selected_item, &scroll_offset, +1, MENU_COUNT);
        if (btn == 2) {
            switch (selected_item) {
                case 0: // Scan Networks — view only
                    do_scan();
                    ui_state = S_SCAN_LIST;
                    render_net_list("Networks");
                    return;
                case 1: // Deauth Targeted
                    do_scan();
                    ui_state = S_DTARGET_LIST;
                    render_net_list("Targeted Target");
                    return;
                case 2: // Deauth Flood
                    do_scan();
                    ui_state = S_DFLOOD_LIST;
                    render_net_list("Flood Target");
                    return;
                case 3: // Deauth All
                    reason   = 1;
                    ui_state = S_DALL_REASON;
                    render_reason_picker("Deauth ALL");
                    return;
                case 4: // Packet Spam
                    do_scan();
                    ui_state = S_PSPAM_LIST;
                    render_net_list("Spam Target");
                    return;
                case 5: // BLE Spam
                    ble_selected  = 0;
                    scroll_offset = 0;
                    selected_item = 0;
                    ui_state      = S_BLE_LIST;
                    render_ble_list();
                    return;
                case 6: // Multi-SSID toggle
                    multi_ssid = !multi_ssid;
                    break;
                case 7: // Stop All
                    stop_deauth();
                    stop_packet_spam();
                    stop_ble_spam();
                    WiFi.mode(WIFI_MODE_AP);
                    WiFi.softAP(AP_SSID, AP_PASS);
                    break;
            }
        }
        render_main_menu();
        break;

    // ── Scan list (view only) ─────────────────────────────────────────────────
    case S_SCAN_LIST: {
        int total = num_networks + 1;
        if (btn == 0) navigate(&selected_item, &scroll_offset, -1, total);
        if (btn == 1) navigate(&selected_item, &scroll_offset, +1, total);
        if (btn == 2) {
            if (selected_item == 0) { go_main_menu(); render_main_menu(); return; }
            net_target = selected_item - 1;
            ui_state   = S_SCAN_DETAIL;
            render_scan_detail(net_target);
            return;
        }
        render_net_list("Networks");
        break;
    }

    case S_SCAN_DETAIL:
        // Any button goes back to scan list
        ui_state = S_SCAN_LIST;
        render_net_list("Networks");
        break;

    // ── Deauth Targeted — network picker ─────────────────────────────────────
    case S_DTARGET_LIST: {
        int total = num_networks + 1;
        if (btn == 0) navigate(&selected_item, &scroll_offset, -1, total);
        if (btn == 1) navigate(&selected_item, &scroll_offset, +1, total);
        if (btn == 2) {
            if (selected_item == 0) { go_main_menu(); render_main_menu(); return; }
            net_target = selected_item - 1;
            reason     = 1;
            ui_state   = S_DTARGET_REASON;
            char hdr[22];
            String ssid = WiFi.SSID(net_target);
            if (ssid.length() == 0) ssid = "(hidden)";
            snprintf(hdr, sizeof(hdr), "#%d %.13s", net_target, ssid.c_str());
            render_reason_picker(hdr);
            return;
        }
        render_net_list("Targeted Target");
        break;
    }

    case S_DTARGET_REASON: {
        if (btn == 0 && reason < 24) reason++;
        if (btn == 1 && reason >  1) reason--;
        if (btn == 2) {
            if (multi_ssid) {
                int targets[MAX_DEAUTH_TARGETS];
                int count = collect_same_ssid(net_target, targets);
                start_deauth_multi(targets, count, reason);
            } else {
                start_deauth(net_target, DEAUTH_TYPE_SINGLE, reason);
            }
            graph_reset();
            ui_state = S_DTARGET_RUNNING;
            render_dtarget_running();
            return;
        }
        char hdr[22];
        String ssid = WiFi.SSID(net_target);
        if (ssid.length() == 0) ssid = "(hidden)";
        snprintf(hdr, sizeof(hdr), "#%d %.13s", net_target, ssid.c_str());
        render_reason_picker(hdr);
        break;
    }

    case S_DTARGET_RUNNING:
        if (btn == 0) { cycle_view(-1); render_dtarget_running(); }
        if (btn == 1) { cycle_view(+1); render_dtarget_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_deauth();
            WiFi.mode(WIFI_MODE_AP); WiFi.softAP(AP_SSID, AP_PASS);
            go_main_menu(); render_main_menu();
        }
        break;

    // ── Deauth Flood — network picker ─────────────────────────────────────────
    case S_DFLOOD_LIST: {
        int total = num_networks + 1;
        if (btn == 0) navigate(&selected_item, &scroll_offset, -1, total);
        if (btn == 1) navigate(&selected_item, &scroll_offset, +1, total);
        if (btn == 2) {
            if (selected_item == 0) { go_main_menu(); render_main_menu(); return; }
            net_target = selected_item - 1;
            reason     = 1;
            ui_state   = S_DFLOOD_REASON;
            char hdr[22];
            String ssid = WiFi.SSID(net_target);
            if (ssid.length() == 0) ssid = "(hidden)";
            snprintf(hdr, sizeof(hdr), "#%d %.13s", net_target, ssid.c_str());
            render_reason_picker(hdr);
            return;
        }
        render_net_list("Flood Target");
        break;
    }

    case S_DFLOOD_REASON: {
        if (btn == 0 && reason < 24) reason++;
        if (btn == 1 && reason >  1) reason--;
        if (btn == 2) {
            if (multi_ssid) {
                int targets[MAX_DEAUTH_TARGETS];
                int count = collect_same_ssid(net_target, targets);
                start_flood_deauth_multi(targets, count, reason);
            } else {
                start_flood_deauth(net_target, reason);
            }
            graph_reset();
            ui_state = S_DFLOOD_RUNNING;
            render_dflood_running();
            return;
        }
        char hdr[22];
        String ssid = WiFi.SSID(net_target);
        if (ssid.length() == 0) ssid = "(hidden)";
        snprintf(hdr, sizeof(hdr), "#%d %.13s", net_target, ssid.c_str());
        render_reason_picker(hdr);
        break;
    }

    case S_DFLOOD_RUNNING:
        if (btn == 0) { cycle_view(-1); render_dflood_running(); }
        if (btn == 1) { cycle_view(+1); render_dflood_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_deauth();
            WiFi.mode(WIFI_MODE_AP); WiFi.softAP(AP_SSID, AP_PASS);
            go_main_menu(); render_main_menu();
        }
        break;

    // ── Deauth All ────────────────────────────────────────────────────────────
    case S_DALL_REASON:
        if (btn == 0 && reason < 24) reason++;
        if (btn == 1 && reason >  1) reason--;
        if (btn == 2) {
            start_deauth(0, DEAUTH_TYPE_ALL, reason);
            graph_reset();
            ui_state = S_DALL_RUNNING;
            render_dall_running();
            return;
        }
        render_reason_picker("Deauth ALL");
        break;

    case S_DALL_RUNNING:
        if (btn == 0) { cycle_view(-1); render_dall_running(); }
        if (btn == 1) { cycle_view(+1); render_dall_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_deauth();
            WiFi.mode(WIFI_MODE_AP); WiFi.softAP(AP_SSID, AP_PASS);
            go_main_menu(); render_main_menu();
        }
        break;

    // ── Packet Spam ───────────────────────────────────────────────────────────
    case S_PSPAM_LIST: {
        int total = num_networks + 1;
        if (btn == 0) navigate(&selected_item, &scroll_offset, -1, total);
        if (btn == 1) navigate(&selected_item, &scroll_offset, +1, total);
        if (btn == 2) {
            if (selected_item == 0) { go_main_menu(); render_main_menu(); return; }
            net_target = selected_item - 1;
            if (multi_ssid) {
                int targets[MAX_SPAM_TARGETS];
                int count = collect_same_ssid(net_target, targets);
                static uint8_t multi_bssids[MAX_SPAM_TARGETS][6];
                static uint8_t multi_channels[MAX_SPAM_TARGETS];
                for (int i = 0; i < count; i++) {
                    memcpy(multi_bssids[i], WiFi.BSSID(targets[i]), 6);
                    multi_channels[i] = WiFi.channel(targets[i]);
                }
                start_packet_spam_multi(multi_bssids, multi_channels, count);
            } else {
                start_packet_spam(WiFi.BSSID(net_target), WiFi.channel(net_target));
            }
            graph_reset();
            ui_state = S_PSPAM_RUNNING;
            render_pspam_running();
            return;
        }
        render_net_list("Spam Target");
        break;
    }

    case S_PSPAM_RUNNING:
        if (btn == 0) { cycle_view(-1); render_pspam_running(); }
        if (btn == 1) { cycle_view(+1); render_pspam_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_packet_spam();
            go_main_menu(); render_main_menu();
        }
        break;

    // ── BLE Spam ──────────────────────────────────────────────────────────────
    case S_BLE_LIST: {
        int total = BLE_DEVICE_COUNT + 1;
        if (btn == 0) navigate(&ble_selected, &scroll_offset, -1, total);
        if (btn == 1) navigate(&ble_selected, &scroll_offset, +1, total);
        if (btn == 2) {
            if (ble_selected == 0) {
                // Scan & Target mode
                ui_state = S_BLE_SCAN_SCANNING;
                display.clearDisplay();
                draw_header("BLE Scanning...");
                display.setTextSize(1);
                display.setCursor(10, 26); display.print("Scanning 5 seconds");
                display.setCursor(10, 36); display.print("for BLE devices...");
                display.display();
                ble_scan_start();
                unsigned long t = millis();
                while (ble_scanning && millis() - t < 6000) delay(100);
                ble_scan_stop();
                reset_list();
                ui_state = S_BLE_SCAN_LIST;
                render_ble_scan_list();
                return;
            }
            start_ble_spam((ble_device_type_t)(ble_selected - 1));
            graph_reset();
            ui_state = S_BLE_RUNNING;
            render_ble_running();
            return;
        }
        render_ble_list();
        break;
    }

    case S_BLE_RUNNING:
        if (btn == 0) { cycle_view(-1); render_ble_running(); }
        if (btn == 1) { cycle_view(+1); render_ble_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_ble_spam();
            go_main_menu(); render_main_menu();
        }
        break;

    case S_BLE_SCAN_LIST: {
        int total = ble_scan_count + 1;
        if (btn == 0) navigate(&ble_selected, &scroll_offset, -1, total);
        if (btn == 1) navigate(&ble_selected, &scroll_offset, +1, total);
        if (btn == 2) {
            if (ble_selected == 0 || ble_scan_count == 0) {
                reset_list();
                ui_state = S_BLE_LIST;
                render_ble_list();
                return;
            }
            int ti = ble_selected - 1;
            start_ble_target(ble_scan_results[ti].addr, ble_scan_results[ti].addr_type);
            graph_reset();
            ui_state = S_BLE_TARGET_RUNNING;
            render_ble_target_running();
            return;
        }
        render_ble_scan_list();
        break;
    }

    case S_BLE_TARGET_RUNNING:
        if (btn == 0) { cycle_view(-1); render_ble_target_running(); }
        if (btn == 1) { cycle_view(+1); render_ble_target_running(); }
        if (btn == 2) {
            view_mode = VIEW_BASIC;
            stop_ble_spam();
            go_main_menu(); render_main_menu();
        }
        break;

    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Button polling
// ─────────────────────────────────────────────────────────────────────────────
static void poll_buttons() {
    const int pins[3] = { BUTTON_UP, BUTTON_DOWN, BUTTON_SELECT };
    unsigned long now = millis();
    for (int i = 0; i < 3; i++) {
        bool pressed = (digitalRead(pins[i]) == LOW);
        if (pressed && !btn_held[i] && (now - last_btn_ms[i] >= BUTTON_DEBOUNCE_MS)) {
            btn_held[i]    = true;
            last_btn_ms[i] = now;
            handle_button(i);
        } else if (!pressed) {
            btn_held[i] = false;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────
void oled_ui_init() {
    Wire.begin(OLED_SDA, OLED_SCL);

    // Probe I2C address before calling display.begin() so we don't hang
    Wire.beginTransmission(OLED_ADDR);
    bool found = (Wire.endTransmission() == 0);

    if (found) {
        display_present = display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
    }

    if (display_present) {
        display.setTextWrap(false);
        display.setTextSize(1);
        display.setTextColor(SSD1306_WHITE);

        // Splash
        display.clearDisplay();
        draw_header("ESP32 Deauther");
        display.setCursor(10, 16); display.print("   OLED Interface");
        display.setCursor(10, 26); display.print(" github/tesa-klebeband");
        display.setCursor(18, 40); display.print("UP  DOWN  SELECT");
        draw_footer("^", "ok", "v");
        display.display();
        delay(2000);
    } else {
        // Headless mode — announce on Serial
        DEBUG_PRINTLN("=== ESP32 Deauther ===");
        DEBUG_PRINTLN("No OLED detected. Running headless via Serial.");
        DEBUG_PRINTLN("Buttons: UP=cycle view  DOWN=cycle view  SELECT=stop/confirm");
        DEBUG_PRINTLN("Waiting for button input...");
    }

    pinMode(BUTTON_UP,     INPUT_PULLUP);
    pinMode(BUTTON_DOWN,   INPUT_PULLUP);
    pinMode(BUTTON_SELECT, INPUT_PULLUP);

    go_main_menu();
    if (display_present) render_main_menu();
    else {
        DEBUG_PRINTLN("Menu: [No OLED] SELECT to start default attack (Deauth All)");
        DEBUG_PRINTLN("Connect OLED for full menu access.");
    }
}

void oled_ui_loop() {
    poll_buttons();
    packet_spam_loop();
    ble_spam_loop();

    static unsigned long last_refresh = 0;
    unsigned long now = millis();
    if (now - last_refresh >= 500) {
        last_refresh = now;

        // Push graph sample every other refresh (≈1 sec)
        static bool graph_tick = false;
        graph_tick = !graph_tick;
        if (graph_tick && is_running_state()) graph_push_sample();

        if (!display_present) {
            // Headless: always print to serial during attacks
            if (is_running_state()) headless_render();
        } else {
            switch (ui_state) {
                case S_DTARGET_RUNNING: render_dtarget_running(); break;
                case S_DFLOOD_RUNNING:  render_dflood_running();  break;
                case S_DALL_RUNNING:    render_dall_running();    break;
                case S_PSPAM_RUNNING:   render_pspam_running();   break;
                case S_BLE_RUNNING:     render_ble_running();     break;
                case S_BLE_TARGET_RUNNING: render_ble_target_running(); break;
                default: break;
            }
        }
    }
}
