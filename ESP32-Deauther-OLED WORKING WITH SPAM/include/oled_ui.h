#ifndef OLED_UI_H
#define OLED_UI_H

// Call once in setup() — initialises display, buttons, and shows splash screen
void oled_ui_init();

// Call every loop() iteration — handles button input and screen refreshes
void oled_ui_loop();

#endif // OLED_UI_H
