#pragma once
// Minimal JSON serialisation for the live stream protocol. Each message is a
// single line (newline-delimited JSON) with a "type" field:
//   {"type":"frame", ...}   {"type":"event", ...}   {"type":"alert", ...}

#include <string>
#include <string_view>

#include "core/types.hpp"

namespace sysmon::json {

std::string escape(std::string_view s);
std::string number(double v);           ///< finite, compact; NaN/Inf become 0
std::string timestamp(double epoch_s);  ///< epoch seconds with millisecond precision

std::string to_json(const MetricsFrame& f, int max_processes);
std::string to_json(const SecurityEvent& e);
std::string to_json(const Alert& a);

}  // namespace sysmon::json
