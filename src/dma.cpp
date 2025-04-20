#include "dma.hh"

DMA::DMA(bool use_memory_map) {
    LPCSTR args[8] = {"", "-device", "fpga://algo=0", "", "", "", "", ""};
    DWORD argc = 3;
    
    std::string path;
    if (use_memory_map) {
        auto current_path = std::filesystem::current_path();
        path = (current_path / "memory_map.txt").string();

        bool dumped = std::filesystem::exists(path) || dump_memory_map();
        if (!dumped) {
            std::cerr << "[DMA] Could not dump memory map.\n";
        }
        else {
            args[argc++] = "-memmap";
            args[argc++] = path.c_str();
        }
    }

    handle = VMMDLL_Initialize(argc, args);
    if (!handle) {
        std::cerr << "[DMA] Failed to initialize.\n";
        return;
    }

    clean_fpga();
}

DMA::~DMA() {
    if (handle) {
        VMMDLL_Close(handle);
        handle = nullptr;
    }
}

bool DMA::dump_memory_map() {
    LPCSTR args[] = { "-device", "fpga", "-waitinitialize", "-norefresh", "", "" };
    int argc = 4;

    VMM_HANDLE temp_handle = VMMDLL_Initialize(argc, args);
    if (!temp_handle) {
        std::cerr << "[DMA] Failed to open handle.\n";
        return false;
    }

    PVMMDLL_MAP_PHYSMEM p_phys_mem_map = nullptr;
    if (!VMMDLL_Map_GetPhysMem(temp_handle, &p_phys_mem_map)) {
        std::cerr << "[DMA] Failed to get physical memory map.\n";

        VMMDLL_Close(temp_handle);
        return false;
    }

    if (!p_phys_mem_map || p_phys_mem_map->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION || p_phys_mem_map->cMap == 0) {
        std::cerr << "[DMA] Invalid memory map.\n";
        VMMDLL_MemFree(p_phys_mem_map);
        VMMDLL_Close(temp_handle);
        return false;
    }

    std::stringstream sb;
    for (DWORD i = 0; i < p_phys_mem_map->cMap; ++i) {
        sb << std::hex << p_phys_mem_map->pMap[i].pa << " " << (p_phys_mem_map->pMap[i].pa + p_phys_mem_map->pMap[i].cb - 1) << std::endl;
    }

    auto current_path = std::filesystem::current_path();
    std::ofstream file(current_path / "memory_map.txt");
    if (!file.is_open()) {
        VMMDLL_MemFree(p_phys_mem_map);
        VMMDLL_Close(temp_handle);
        return false;
    }

    file << sb.str();
    file.close();

    VMMDLL_MemFree(p_phys_mem_map);
    VMMDLL_Close(temp_handle);

    return true;
}

bool DMA::clean_fpga() {
    ULONG64 fpga_id = 0, version_major = 0, version_minor = 0;

    if (!VMMDLL_ConfigGet(handle, LC_OPT_FPGA_FPGA_ID, &fpga_id) && VMMDLL_ConfigGet(handle, LC_OPT_FPGA_VERSION_MAJOR, &version_major) && VMMDLL_ConfigGet(handle, LC_OPT_FPGA_VERSION_MINOR, &version_minor)) {
        std::cout << "[DMA] Failed to lookup FPGA device. Attempting to continue initializing.\n";
        return false;
    }

    if ((version_major >= 4) && ((version_major >= 5) || (version_minor >= 7))) {
        HANDLE lc_handle;
        LC_CONFIG config = { .dwVersion = LC_CONFIG_VERSION, .szDevice = "existing" };
        lc_handle = LcCreate(&config);

        if (!lc_handle) {
            std::cout << "[DMA] Failed to create FPGA device handle. Attempting to continue initializing.\n";
            return false;
        }

        LcCommand(lc_handle, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, sizeof(abort_2), abort_2, NULL, NULL);
        LcClose(lc_handle);
    }

    return true;
}