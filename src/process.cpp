#include "process.hh"

PROCESS::PROCESS(DMA& dma, const std::string& process_name) : dma(dma) {
    process_id = dma.get_process_id(process_name);
}

uint64_t PROCESS::get_base_address(const std::string& module_name) const {
    PVMMDLL_MAP_MODULEENTRY module_info;

    if (!VMMDLL_Map_GetModuleFromNameU(dma.handle, process_id, module_name.c_str(), &module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
        std::cerr << "[PROCESS] Failed to find base address for module: " + module_name << ".\n";
    }

    return static_cast<uint64_t>(module_info->vaBase);
}

bool PROCESS::fix_cr3(const std::string& process_name) {
    PVMMDLL_MAP_MODULEENTRY module_entry;

    bool result = VMMDLL_Map_GetModuleFromNameU(dma.handle, process_id, process_name.c_str(), &module_entry, NULL);
    if (result) {
        return true;
    }

    if (!VMMDLL_InitializePlugins(dma.handle)) {
        std::cerr << "[PROCESS] Failed to initialize plugins.\n";
        return false;
    }

    Sleep(500);

    while (true) {
        BYTE bytes[4] = { 0 };
        DWORD i = 0;
        auto nt = VMMDLL_VfsReadW(dma.handle, (LPWSTR)L"\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);
        if (nt == VMMDLL_STATUS_SUCCESS && atoi((LPSTR)bytes) == 100)
            break;
        Sleep(100);
    }

    VMMDLL_VFS_FILELIST2 VfsFileList;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    VfsFileList.h = 0;
    VfsFileList.pfnAddDirectory = nullptr;
    VfsFileList.pfnAddFile = cb_add_file;

    result = VMMDLL_VfsListU(dma.handle, (LPSTR)"\\misc\\procinfo\\", &VfsFileList);
    if (!result)
        return false;

    const size_t buffer_size = cb_size;
    std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
    DWORD j = 0;
    auto nt = VMMDLL_VfsReadW(dma.handle, (LPWSTR)L"\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
    if (nt != VMMDLL_STATUS_SUCCESS)
        return false;

    std::vector<uint64_t> possible_dtbs;
    std::string lines(reinterpret_cast<char*>(bytes.get()));
    std::istringstream iss(lines);
    std::string line;

    while (std::getline(iss, line)) {
        Info info = {};
        std::istringstream info_ss(line);
        if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernel_address >> info.name) {
            if (info.process_id == 0 || process_name.find(info.name) != std::string::npos) {
                possible_dtbs.push_back(info.dtb);
            }
        }
    }

    for (size_t i = 0; i < possible_dtbs.size(); i++) {
        auto dtb = possible_dtbs[i];
        VMMDLL_ConfigSet(dma.handle, VMMDLL_OPT_PROCESS_DTB | process_id, dtb);
        result = VMMDLL_Map_GetModuleFromNameU(dma.handle, process_id, process_name.c_str(), &module_entry, NULL);
        if (result) {
            static ULONG64 pml4_first[512];
            static ULONG64 pml4_second[512];
            DWORD read_size;

            if (!VMMDLL_MemReadEx(dma.handle, -1, dtb, reinterpret_cast<PBYTE>(pml4_first), sizeof(pml4_first), &read_size,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
#ifdef _DEBUG
                std::cerr << "[PROCESS] Failed to read PML4 the first time.\n";
#endif
                return false;
            }

            if (!VMMDLL_MemReadEx(dma.handle, -1, dtb, reinterpret_cast<PBYTE>(pml4_second), sizeof(pml4_second), &read_size,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
#ifdef _DEBUG
                std::cerr << "[PROCESS] Failed to read PML4 the second time.\n";
#endif
                return false;
            }

            if (memcmp(pml4_first, pml4_second, sizeof(pml4_first)) != 0) {
#ifdef _DEBUG
                std::cerr << "[PROCESS] PML4 mismatch between reads.\n";
#endif
                return false;
            }

            VMMDLL_MemReadEx((VMM_HANDLE)-666, 333, (ULONG64)pml4_first, nullptr, 0, nullptr, 0);
            VMMDLL_ConfigSet(dma.handle, VMMDLL_OPT_PROCESS_DTB | process_id, 666);

            return true;
        }
    }

    std::cerr << "[PROCESS] Failed to patch process: " << process_name << ".\n";
    return false;
}

bool PROCESS::virtual_to_physical(uint64_t virtual_address, uint64_t& physical_address) const {
    return VMMDLL_VirtualToPhysical(dma.handle, virtual_address, &physical_address);
}

bool PROCESS::read(uint64_t address, void* buffer, size_t size) const {
    if (address == 0) {
        return false;
    }

    DWORD read_size = 0;
    if (!VMMDLL_MemReadEx(dma.handle, this->process_id, address, static_cast<PBYTE>(buffer), size, &read_size, VMMDLL_FLAG_NOCACHE)) {
        std::cerr << "[PROCESS] Failed to read memory at 0x" << std::hex << address << " (Process ID: " << std::dec << process_id << ").\n";
        return false;
    }

    return read_size == size;
}

uint64_t PROCESS::read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
    uint64_t result = read<uint64_t>(base + offsets.at(0));
    for (size_t i = 1; i < offsets.size(); ++i) {
        result = read<uint64_t>(result + offsets.at(i));
    }
    return result;
}

bool PROCESS::write(uint64_t address, void* buffer, size_t size, uint32_t pid) const {
    if (address == 0) {
        return false;
    }

    uint32_t target_pid = (pid == 0) ? this->process_id : pid;

    if (!VMMDLL_MemWrite(dma.handle, target_pid, address, static_cast<PBYTE>(buffer), size)) {
        std::cerr << "[PROCESS] Failed to write memory at 0x" << std::hex << address
            << " (Process ID: " << std::dec << target_pid << ").\n";
        return false;
    }

    return true;
}

VMMDLL_SCATTER_HANDLE PROCESS::create_scatter(DWORD pid) const {
    DWORD target_pid = (pid != 0) ? pid : this->process_id;
    VMMDLL_SCATTER_HANDLE scatter_handle = VMMDLL_Scatter_Initialize(dma.handle, target_pid, scatter_flags);
    if (!scatter_handle) {
        std::cerr << "[PROCESS] Failed to create scatter handle.\n";
    }
    return scatter_handle;
}


void PROCESS::close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const {
    if (scatter_handle) {
        VMMDLL_Scatter_CloseHandle(scatter_handle);
        scatter_counts.erase(scatter_handle);
    }
}

bool PROCESS::add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (address == 0) {
        return false;
    }

    if (!VMMDLL_Scatter_PrepareEx(scatter_handle, address, size, static_cast<PBYTE>(buffer), NULL)) {
        std::cerr << "[PROCESS] Failed to prepare scatter read at 0x" << std::hex << address << std::dec << ".\n";
        return false;
    }
    ++scatter_counts[scatter_handle];

    return true;
}

bool PROCESS::add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (address == 0) {
        return false;
    }

    if (!VMMDLL_Scatter_PrepareWrite(scatter_handle, address, static_cast<PBYTE>(buffer), size)) {
        std::cerr << "[PROCESS] Failed to prepare scatter write at 0x" << std::hex << address << std::dec << ".\n";
        return false;
    }
    ++scatter_counts[scatter_handle];

    return true;
}

bool PROCESS::execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, DWORD pid) const {
    DWORD target_pid = (pid != 0) ? pid : this->process_id;
    
    bool success = true;

    auto it = scatter_counts.find(scatter_handle);
    if (it == scatter_counts.end() || it->second == 0) {
        return success;
    }

    if (!VMMDLL_Scatter_Execute(scatter_handle)) {
        std::cerr << "[PROCESS] Failed to execute scatter.\n";
        success = false;
    }

    if (!VMMDLL_Scatter_Clear(scatter_handle, target_pid, scatter_flags)) {
        std::cerr << "[PROCESS] Failed to clear scatter.\n";
        success = false;
    }
    scatter_counts[scatter_handle] = 0;

    return success;
}

uint64_t PROCESS::cb_size = 0x80000;
VOID PROCESS::cb_add_file(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo) {
    if (strcmp(uszName, "dtb.txt") == 0)
        cb_size = cb;
}