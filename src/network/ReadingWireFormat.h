#pragma once

#include <string>

#include <ArduinoJson.h>

namespace pm {
namespace reading_wire {

// A durable reading is loaded from a page whose complete payload is bounded
// by the server-sync policy. Keep an independent per-record guard here as
// this translator is also used by the local history endpoint.
constexpr std::size_t kMaximumEncodedRecordBytes = 8U * 1024U;

// Translate the durable on-card record into the shared pm-protocol/1.0.0
// server Reading shape. Invalid measurements are represented by JSON null,
// never fabricated zeroes.
bool append(JsonArray output, const std::string &encoded_record);

} // namespace reading_wire
} // namespace pm
