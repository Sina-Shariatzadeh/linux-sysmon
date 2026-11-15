#include <sys/statvfs.h>

#include <algorithm>
#include <filesystem>
#include <set>

#include "collectors/collectors.hpp"

namespace sysmon {
namespace {

constexpr double kSectorBytes = 512.0;  // /proc/diskstats always uses 512-byte sectors

bool is_real_fs(const std::string& t) {
    static const std::set<std::string> kTypes{"ext2", "ext3",  "ext4",    "xfs",     "btrfs",
                                              "zfs",  "f2fs",  "vfat",    "exfat",   "ntfs",
                                              "ntfs3", "fuseblk", "reiserfs", "jfs", "bcachefs"};
    return kTypes.count(t) > 0;
}

bool starts_with(const std::string& s, std::string_view p) { return s.rfind(p, 0) == 0; }

}  // namespace

DiskCollector::DiskCollector(std::string proc_root, std::string sys_root)
    : proc_root_(std::move(proc_root)), sys_root_(std::move(sys_root)) {
    if (auto text = parsers::read_file(proc_root_ + "/diskstats"))
        for (auto& d : parsers::parse_diskstats(*text)) prev_[d.device] = d;
    prev_time_ = SteadyClock::now();
}

bool DiskCollector::is_physical_disk(const std::string& dev) const {
    if (starts_with(dev, "loop") || starts_with(dev, "ram") || starts_with(dev, "fd") || starts_with(dev, "sr"))
        return false;
    // Whole disks (not partitions) appear directly under /sys/block.
    std::error_code ec;
    const std::filesystem::path block = std::filesystem::path(sys_root_) / "block";
    if (std::filesystem::is_directory(block, ec)) return std::filesystem::exists(block / dev, ec);
    return true;  // no /sys available (e.g. tests): accept everything not excluded above
}

std::vector<FilesystemUsage> DiskCollector::filesystems() const {
    std::vector<FilesystemUsage> out;
    const auto text = parsers::read_file(proc_root_ + "/mounts");
    if (!text) return out;

    std::set<std::string> seen_devices;
    for (const auto& m : parsers::parse_mounts(*text)) {
        if (!is_real_fs(m.fs_type) || !seen_devices.insert(m.device).second) continue;
        struct statvfs st {};
        if (::statvfs(m.mount_point.c_str(), &st) != 0 || st.f_blocks == 0) continue;
        FilesystemUsage fs;
        fs.mount_point = m.mount_point;
        fs.device = m.device;
        fs.fs_type = m.fs_type;
        const uint64_t frsize = st.f_frsize ? st.f_frsize : st.f_bsize;
        fs.total_bytes = static_cast<uint64_t>(st.f_blocks) * frsize;
        fs.avail_bytes = static_cast<uint64_t>(st.f_bavail) * frsize;
        const uint64_t free_bytes = static_cast<uint64_t>(st.f_bfree) * frsize;
        fs.used_bytes = fs.total_bytes - free_bytes;
        // Same formula as df: used / (used + available to unprivileged users)
        const double denom = static_cast<double>(fs.used_bytes + fs.avail_bytes);
        fs.used_pct = denom > 0 ? 100.0 * static_cast<double>(fs.used_bytes) / denom : 0.0;
        out.push_back(std::move(fs));
    }
    return out;
}

DiskSnapshot DiskCollector::sample() {
    DiskSnapshot snap;
    const auto now = SteadyClock::now();
    const double secs = std::chrono::duration<double>(now - prev_time_).count();

    if (auto text = parsers::read_file(proc_root_ + "/diskstats")) {
        std::map<std::string, DiskCounters> current;
        for (auto& d : parsers::parse_diskstats(*text)) {
            if (!is_physical_disk(d.device)) continue;
            auto it = prev_.find(d.device);
            if (it != prev_.end() && secs > 0) {
                const auto& p = it->second;
                auto rate = [secs](uint64_t a, uint64_t b) { return b >= a ? static_cast<double>(b - a) / secs : 0.0; };
                DiskIo io;
                io.device = d.device;
                io.read_bps = rate(p.sectors_read, d.sectors_read) * kSectorBytes;
                io.write_bps = rate(p.sectors_written, d.sectors_written) * kSectorBytes;
                io.reads_ps = rate(p.reads_completed, d.reads_completed);
                io.writes_ps = rate(p.writes_completed, d.writes_completed);
                io.util_pct = std::clamp(rate(p.io_ms, d.io_ms) / 10.0, 0.0, 100.0);  // ms per s -> %
                snap.io.push_back(std::move(io));
            }
            current[d.device] = std::move(d);
        }
        prev_ = std::move(current);
    }
    prev_time_ = now;
    snap.filesystems = filesystems();
    return snap;
}

}  // namespace sysmon
