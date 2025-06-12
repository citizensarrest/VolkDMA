#include "dma.hh"

DMA::DMA(bool use_memory_map) {
    LPCSTR args[8] = {"", "-device", "fpga://algo=0", "", "", "", "", ""};
    DWORD argc = 3;
    
    std::string path;
    if (use_memory_map) {
        auto current_path = std::filesystem::current_path();
        path = (current_path / "memory_map.txt").string();

        bool dumped = std::filesystem::exists(path) || this->dump_memory_map();
        if (!dumped) {
            std::cerr << "[DMA] Could not dump memory map.\n";
        }
        else {
            args[argc++] = "-memmap";
            args[argc++] = path.c_str();
        }
    }

    this->handle = VMMDLL_Initialize(argc, args);
    if (!this->handle) {
        std::cerr << "[DMA] Failed to initialize.\n";
        return;
    }

    this->clean_fpga();
}

DMA::~DMA() {
    if (this->handle) {
        VMMDLL_Close(this->handle);
        this->handle = nullptr;
    }
}

DWORD DMA::get_process_id(const std::string& process_name) const {
    DWORD process_id = 0;

    if (!VMMDLL_PidGetFromName(this->handle, process_name.c_str(), &process_id) || process_id == 0) {
        std::cerr << "[PROCESS] Failed to get ID for process: " << process_name << ".\n";
    }

    return process_id;
}

std::vector<DWORD> DMA::get_process_id_list(const std::string& process_name) const {
    std::vector<DWORD> list = { };
    PVMMDLL_PROCESS_INFORMATION process_info = NULL;
    DWORD total_processes = 0;

    if (!VMMDLL_ProcessGetInformationAll(this->handle, &process_info, &total_processes) || total_processes == 0) {
        std::cerr << "[PROCESS] Failed to retrieve process process list.\n";
        return list;
    }

    for (size_t i = 0; i < total_processes; i++) {
        auto process = process_info[i];
        if (strstr(process.szNameLong, process_name.c_str())) {
            list.push_back(process.dwPID);
        }
    }

    return list;
}

uint64_t DMA::find_signature(const char* signature, uint64_t range_start, uint64_t range_end, DWORD process_id) const {
    if (!signature || !*signature || range_start >= range_end) {
        return 0;
    }

    uint64_t size = range_end - range_start;
    std::vector<uint8_t> buffer(size);

    if (!VMMDLL_MemReadEx(this->handle, process_id, range_start, buffer.data(), size, nullptr, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
        return 0;
    }

    const char* pat = signature;
    uint64_t first_match = 0;

    for (uint64_t i = 0; i < size; i++) {
        if (*pat == '\0') {
            break;
        }

        if (*pat == '?' || buffer[i] == this->get_byte(pat)) {
            if (!first_match) {
                first_match = range_start + i;
            }

            pat += (*pat == '?') ? 2 : 3;

            if (*pat == '\0') {
                return first_match;
            }
        }
        else {
            pat = signature;
            first_match = 0;
        }
    }

    return 0;
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

    if (!VMMDLL_ConfigGet(this->handle, LC_OPT_FPGA_FPGA_ID, &fpga_id) && VMMDLL_ConfigGet(this->handle, LC_OPT_FPGA_VERSION_MAJOR, &version_major) && VMMDLL_ConfigGet(this->handle, LC_OPT_FPGA_VERSION_MINOR, &version_minor)) {
        std::cerr << "[DMA] Failed to lookup FPGA device. Attempting to continue initializing.\n";
        return false;
    }

    if ((version_major >= 4) && ((version_major >= 5) || (version_minor >= 7))) {
        HANDLE lc_handle;
        LC_CONFIG config = { .dwVersion = LC_CONFIG_VERSION, .szDevice = "existing" };
        lc_handle = LcCreate(&config);

        if (!lc_handle) {
            std::cerr << "[DMA] Failed to create FPGA device handle. Attempting to continue initializing.\n";
            return false;
        }

        LcCommand(lc_handle, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, sizeof(this->abort_2), this->abort_2, NULL, NULL);
        LcClose(lc_handle);
    }

    return true;
}

uint8_t DMA::get_byte(const char* hex) const {
    char byte[3] = { hex[0], hex[1], 0 };
    return static_cast<uint8_t>(strtoul(byte, nullptr, 16));
}