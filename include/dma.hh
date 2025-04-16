#pragma once

#include "vmmdll.h"

class DMA {
public:
    bool initialize();
    void shutdown();
    VMM_HANDLE get_handle() const;

private:
    VMM_HANDLE handle = nullptr;
};