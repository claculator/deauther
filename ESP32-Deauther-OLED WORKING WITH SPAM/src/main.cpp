#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "definitions.h"
#include "deauth.h"
#include "packet_spam.h"
#include "oled_ui.h"
#include "ble_spam.h"

static int curr_channel = 1;

void setup() {
#ifdef SERIAL_DEBUG
    Serial.begin(115200);
#endif
#ifdef LED
    pinMode(LED, OUTPUT);
#endif
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    ble_spam_init();
    oled_ui_init();
}

void loop() {
    // Channel-hop for deauth-all sniffing
    if (deauth_type == DEAUTH_TYPE_ALL) {
        if (curr_channel > CHANNEL_MAX) curr_channel = 1;
        esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
        curr_channel++;
        delay(10);
    }
    deauth_flood_loop();
    oled_ui_loop();
}
