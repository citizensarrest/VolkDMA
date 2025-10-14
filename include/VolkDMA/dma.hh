#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;

extern "C" void VMMDLL_Close(VMM_HANDLE);
inline constexpr auto vmm_close = [](VMM_HANDLE h) noexcept { if (h) VMMDLL_Close(h); };
using VolkHandle = std::unique_ptr<std::remove_pointer_t<VMM_HANDLE>, decltype(vmm_close)>;

using DWORD = unsigned long;

class DMA {
public:
    explicit DMA(bool use_memory_map = true);

    VolkHandle handle{};

    [[nodiscard]] DWORD get_process_id(const std::string& process_name) const;
    [[nodiscard]] std::vector<DWORD> get_process_id_list(const std::string& process_name) const;
    [[nodiscard]] uint64_t find_signature(const char* signature, uint64_t range_start, uint64_t range_end, DWORD process_id) const;

    template<typename T>
    [[nodiscard]] T read(uint64_t address, DWORD process_id) const;

private:
    bool dump_memory_map();
    bool clean_fpga();
};