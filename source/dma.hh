#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include "vmm/vmmdll.h"

class DMA {
public:
    DMA(bool use_memory_map = true);
    ~DMA();

    VMM_HANDLE handle = nullptr;

    DWORD get_process_id(const std::string& process_name);
    std::vector<DWORD> get_process_id_list(const std::string& process_name);
    uint64_t find_signature(const char* signature, uint64_t range_start, uint64_t range_end, DWORD process_id);

    template<typename T>
    T read(uint64_t address, DWORD process_id) {
        T rdbuf = {};
        VMMDLL_MemReadEx(this->handle, process_id, address, reinterpret_cast<PBYTE>(&rdbuf), sizeof(T), nullptr, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
        return rdbuf;
    }

private:
    unsigned char abort_2[4] = { 0x10, 0x00, 0x10, 0x00 };

    bool dump_memory_map();
    bool clean_fpga();
    uint8_t get_byte(const char* hex);
};