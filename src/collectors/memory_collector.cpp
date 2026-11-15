#include "collectors/collectors.hpp"

namespace sysmon {

MemoryCollector::MemoryCollector(std::string proc_root) : root_(std::move(proc_root)) {}

MemorySnapshot MemoryCollector::sample() const {
    if (auto text = parsers::read_file(root_ + "/meminfo")) return parsers::parse_meminfo(*text);
    return {};
}

}  // namespace sysmon
