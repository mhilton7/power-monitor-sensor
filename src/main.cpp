#include <Arduino.h>

#include "app/Application.h"

namespace {
pm::Application application;
}

void setup() {
  if (!application.begin()) {
    // A failed runtime primitive/NVS initialization is the only terminal boot
    // condition. Missing meter, card, Wi-Fi, time, or server remain degraded.
    for (;;) {
      delay(1000);
    }
  }
}

void loop() {
  // Production work runs in bounded FreeRTOS services and async callbacks.
  delay(1000);
}
