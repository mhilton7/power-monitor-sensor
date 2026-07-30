#pragma once

#include <string>

#include <ArduinoJson.h>

namespace pm {
namespace reading_wire {

// Translate the durable on-card record into the shared pm-protocol/1.0.0
// server Reading shape. Invalid measurements are represented by JSON null,
// never fabricated zeroes.
bool append(JsonArray output, const std::string &encoded_record);

} // namespace reading_wire
} // namespace pm
