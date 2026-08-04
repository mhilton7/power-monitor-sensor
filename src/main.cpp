#include <Arduino.h>

#include "app/Application.h"

// Application::begin() performs the complete production-service bootstrap and
// emits structured diagnostics while doing so. The Arduino core's 8 KiB
// default loop-task stack is insufficient for that nested call path on ESP32-S3
// and fails before configuration recovery can run.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

namespace {
pm::Application application;
}

void setup() {
  if (!application.begin()) {
    // Runtime primitive/NVS failures and a pending OTA candidate that exhausts
    // its bounded local-initialization window stop setup here. Already-created
    // tasks and the local recovery UI remain alive; this loop never performs a
    // blind restart. External Wi-Fi, time, and server outages stay degraded.
    for (;;) {
      delay(1000);
    }
  }
}

void loop() {
  // Production work runs in bounded FreeRTOS services and async callbacks.
  delay(1000);
}
