#include "core/HeapTelemetry.h"

#include <ESP.h>
#include <esp_heap_caps.h>

namespace pm {

HeapSnapshot EspHeapTelemetry::snapshot() const {
  return {
      static_cast<std::uint32_t>(ESP.getFreeHeap()),
      static_cast<std::uint32_t>(ESP.getMinFreeHeap()),
      static_cast<std::uint32_t>(
          heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
      static_cast<std::uint32_t>(heap_caps_get_minimum_free_size(
          MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
      static_cast<std::uint32_t>(heap_caps_get_largest_free_block(
          MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
      static_cast<std::uint32_t>(ESP.getFreePsram()),
      static_cast<std::uint32_t>(
          heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)),
      heap_caps_check_integrity_all(false),
  };
}

} // namespace pm
