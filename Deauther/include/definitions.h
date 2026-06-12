#ifndef DEFINITIONS_H
#define DEFINITIONS_H

// ── WiFi AP ───────────────────────────────────────────────────────────────────
#define AP_SSID "ESP32-Deauther"
#define AP_PASS "esp32wroom32"

// ── Onboard LED ───────────────────────────────────────────────────────────────
#define LED 2

// ── SSD1306 OLED (I2C) ───────────────────────────────────────────────────────
#define OLED_SDA        21
#define OLED_SCL        22
#define OLED_ADDR       0x3C    // Most SSD1306 boards use 0x3C; try 0x3D if blank
#define SCREEN_WIDTH    128
#define SCREEN_HEIGHT   64

// ── Buttons (active LOW — connect pin to GND when pressed) ───────────────────
#define BUTTON_UP       14
#define BUTTON_DOWN     12
#define BUTTON_SELECT   13
#define BUTTON_DEBOUNCE_MS 180  // ms between registered presses

// ── Deauth behaviour ─────────────────────────────────────────────────────────
#define SERIAL_DEBUG
#define CHANNEL_MAX          13
#define NUM_FRAMES_PER_DEAUTH 16
#define DEAUTH_BLINK_TIMES    2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE    0
#define DEAUTH_TYPE_ALL       1
#define DEAUTH_TYPE_FLOOD     2

// ── Debug macros ─────────────────────────────────────────────────────────────
#ifdef SERIAL_DEBUG
  #define DEBUG_PRINT(...)   Serial.print(__VA_ARGS__)
  #define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
  #define DEBUG_PRINTF(...)  Serial.printf(__VA_ARGS__)
#else
  #define DEBUG_PRINT(...)
  #define DEBUG_PRINTLN(...)
  #define DEBUG_PRINTF(...)
#endif

#ifdef LED
  #define BLINK_LED(num_times, blink_duration) blink_led(num_times, blink_duration)
#else
  #define BLINK_LED(...)
#endif

void blink_led(int num_times, int blink_duration);

#endif // DEFINITIONS_H
