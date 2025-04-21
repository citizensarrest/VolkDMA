#pragma once

#include "vmmdll.h"

#include <iostream>
#include <filesystem>
#include <fstream>

class DMA {
public:
    DMA(bool use_memory_map = true);
    ~DMA();
    VMM_HANDLE handle = nullptr;
private:
    bool dump_memory_map();
    bool clean_fpga();
    unsigned char abort_2[4] = { 0x10, 0x00, 0x10, 0x00 };
};