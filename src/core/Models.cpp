#include "core/Models.h"

namespace pm {

const char *meterErrorCode(const MeterError error) {
  switch (error) {
  case MeterError::None:
    return "none";
  case MeterError::Timeout:
    return "pzem_timeout";
  case MeterError::ShortFrame:
    return "pzem_short_frame";
  case MeterError::WrongAddress:
    return "pzem_wrong_address";
  case MeterError::WrongFunction:
    return "pzem_wrong_function";
  case MeterError::ExceptionResponse:
    return "pzem_exception";
  case MeterError::InvalidByteCount:
    return "pzem_invalid_byte_count";
  case MeterError::CrcMismatch:
    return "pzem_crc_mismatch";
  case MeterError::ImplausibleValue:
    return "pzem_implausible_value";
  case MeterError::UartFailure:
    return "pzem_uart_failure";
  }
  return "pzem_unknown_error";
}

} // namespace pm
