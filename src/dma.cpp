#include "dma.hh"

#include <iostream>

bool DMA::initialize() {
    const char* args[] = { "-device", "fpga", "-waitinitialize", "-norefresh" };
    handle = VMMDLL_Initialize(4, args);

    if (!handle) {
        std::cerr << "[DMA] Failed to initialize." << "\n";
        return false;
    }

    return true;
}

void DMA::shutdown() {
    if (handle) {
        VMMDLL_Close(handle);
        handle = nullptr;
    }
}

VMM_HANDLE DMA::get_handle() const {
    return handle;
}