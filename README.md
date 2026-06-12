# deauther

> **Legal Disclaimer** — Deauthentication attacks and packet flooding disrupt wireless communication. Using this tool on networks you do not own or do not have explicit written permission to test is **illegal** in most jurisdictions (e.g., the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK). This project is intended solely for **authorized security research, penetration testing, and educational use on your own equipment**. The author assumes no liability for misuse.

A self-contained Wi-Fi / BLE security research tool for the barebones ESP, navigated entirely from a 128×64 OLED display and three physical buttons.No serial terminal or other computer needed.

---

## Features

- **Scan Networks** — passive scan with per-AP detail view (SSID, BSSID, channel, RSSI, encryption)
- **Deauth Targeted** — sniff-based deauthentication against a chosen AP and its associated stations
- **Deauth Flood** — broadcast-flood deauth against a chosen AP
- **Deauth All** — channel-hopping (ch 1–13) deauth targeting every visible AP simultaneously
- **Packet Spam** — probe-request flood against a selected network (essentially a DOS attack, but much weaker)
- **BLE Spam** — scan for nearby BLE devices and flood them with advertisement packets (under development)
- **Multi-SSID mode** — toggle to attack every AP sharing the same SSID in one pass
- **Live stats overlay** — switch between Basic, Advanced, and scrolling Graph views during any active attack (overlay may have issues)
- **Stop All** — single menu action to halt all attacks and return to the main menu

---

## Hardware

| Component | Details |
|-----------|---------|
| MCU | ESP32 (WROOM or standard)|
| Display | SSD1306 128×64 OLED (I²C) |
| SDA | GPIO 21 |
| SCL | GPIO 22 |
| I²C address | `0x3C` (try `0x3D` if screen is blank) |
| Button UP | GPIO 14 (active-LOW, internal pull-up) |
| Button DOWN | GPIO 12 (active-LOW, internal pull-up) |
| Button SELECT | GPIO 13 (active-LOW, internal pull-up) |
| Status LED | GPIO 2 (onboard) |

Wire each button between its GPIO pin and GND.

---

## Building & Flashing

This project uses [PlatformIO](https://platformio.org/).

**1. Install PlatformIO** (VS Code extension or CLI)

**2. Clone the repo**
```bash
git clone https://github.com/claculator/deauther.git
cd deauther
```

**3. Build and upload**
```bash
pio run --target upload
```

Serial debug output is enabled by default. To disable it, remove or comment out `#define SERIAL_DEBUG` in `include/definitions.h`.

---

## Dependencies

Managed automatically by PlatformIO via `platformio.ini`:

- [Adafruit SSD1306](https://github.com/adafruit/Adafruit_SSD1306) `^2.5.7`
- [Adafruit GFX Library](https://github.com/adafruit/Adafruit-GFX-Library) `^1.11.5`

---

## Navigation

The UI is driven by three buttons:

| Button | Idle / List | Attack running |
|--------|-------------|----------------|
| **UP** | Scroll up / increment value | Cycle view (Basic → Advanced → Graph) |
| **DOWN** | Scroll down / decrement value | Cycle view (reverse) |
| **SELECT** | Confirm selection | — |

From any attack screen, navigate to **Stop All** on the main menu to stop any ongoing attacks.

---

## Configuration

All tuneable constants live in `include/definitions.h`:

```c
#define AP_SSID              "ESP32-Deauther"   // Brodcasted AP name
#define AP_PASS              "esp32wroom32"      // Brodcasted AP password
#define CHANNEL_MAX          13                  // Highest 2.4 GHz channel to hop
#define NUM_FRAMES_PER_DEAUTH 16                 // Frames per deauth burst
#define BUTTON_DEBOUNCE_MS   180                 // Button debounce window (ms)
#define OLED_ADDR            0x3C                // I²C address (0x3D on some boards)
```

---

## Project Structure

```
├── include/
│   ├── definitions.h    # Pin map, timing constants, debug macros
│   ├── deauth.h         # Deauth API (targeted / flood / all-channel)
│   ├── packet_spam.h    # Probe-request spam API
│   ├── ble_spam.h       # BLE advertisement spam API
│   ├── oled_ui.h        # OLED UI init / loop declarations
│   └── types.h          # Shared type definitions
├── src/
│   ├── main.cpp         # setup() / loop() — ties everything together
│   └── oled_ui.cpp      # Full menu state machine + display rendering
└── platformio.ini       # PlatformIO build configuration
```

---

## How It Works

**Deauth attacks** exploit the unauthenticated 802.11 management frame standard: the ESP32 injects forged deauthentication frames (reason code selectable from the menu, but most devices will not see the reason code) that cause stations to disconnect from their AP. The "Deauth All" mode hops channels continuously so every visible network on the 2.4 GHz band is targeted in rotation.

**Packet Spam** floods a target AP with probe requests, which can stress AP management queues.

**BLE Spam** broadcasts crafted BLE advertisement packets at high repetition to a scanned target device. This is still in progress, and may not work as intended.

---

## License

GNU General Public License v3.0, see `LICENSE` for details.
