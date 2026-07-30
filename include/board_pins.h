#pragma once

#include <cstdint>

namespace pm::pins {
inline constexpr int PZEM_UART_TX = 17;
inline constexpr int PZEM_UART_RX = 18;
inline constexpr int SD_CS = 10;
inline constexpr int SD_MOSI = 11;
inline constexpr int SD_SCK = 12;
inline constexpr int SD_MISO = 13;
inline constexpr int PZEM_UART_NUMBER = 1;
inline constexpr std::uint32_t PZEM_BAUD = 9600;
inline constexpr std::uint32_t SERIAL_BAUD = 115200;
} // namespace pm::pins
