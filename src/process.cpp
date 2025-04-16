#include "process.hh"

#include <sstream>
#include <iostream>

PROCESS::PROCESS(VMM_HANDLE handle, const std::string& process_name)
    : handle(handle)
{
    DWORD temp_pid = 0;

    if (!VMMDLL_PidGetFromName(handle, process_name.c_str(), &temp_pid) || temp_pid == 0) {
        std::cerr << "[PROCESS] Failed to get PID for process: " << process_name << ".\n";
    }
    else {
        pid = static_cast<int>(temp_pid);
    }
}

uintptr_t PROCESS::get_base_address(const std::string& module_name) const {
    PVMMDLL_MAP_MODULEENTRY module_info;

    if (!VMMDLL_Map_GetModuleFromNameU(handle, pid, module_name.c_str(), &module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
        std::cerr << "[PROCESS] Failed to find base address for module: " + module_name << ".\n";
    }

    return static_cast<uintptr_t>(module_info->vaBase);
}

bool PROCESS::read(uintptr_t address, void* buffer, size_t size) const {
    DWORD read_size = 0;
    if (!VMMDLL_MemReadEx(this->handle, this->pid, address, static_cast<PBYTE>(buffer), size, &read_size, VMMDLL_FLAG_NOCACHE)) {
        std::cerr << "[PROCESS] Failed to read memory at 0x" << std::hex << address << " (PID: " << std::dec << pid << ").\n";
        return false;
    }

    return read_size == size;
}

bool PROCESS::write(uintptr_t address, void* buffer, size_t size) const {
    if (!VMMDLL_MemWrite(this->handle, this->pid, address, static_cast<PBYTE>(buffer), size)) {
        std::cerr << "[PROCESS] Failed to write memory at 0x" << std::hex << address << " (PID: " << std::dec << pid << ").\n";
        return false;
    }

    return true;
}

VMMDLL_SCATTER_HANDLE PROCESS::create_scatter() const {
    VMMDLL_SCATTER_HANDLE scatter_handle = VMMDLL_Scatter_Initialize(this->handle, this->pid, VMMDLL_FLAG_NOCACHE);
    if (!scatter_handle) {
        std::cerr << "[PROCESS] Failed to create scatter handle." << "\n";
    }
    return scatter_handle;
}

void PROCESS::close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const {
    if (scatter_handle) {
        VMMDLL_Scatter_CloseHandle(scatter_handle);
    }
}

bool PROCESS::add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (!VMMDLL_Scatter_PrepareEx(scatter_handle, address, size, static_cast<PBYTE>(buffer), NULL)) {
        std::cerr << "[PROCESS] Failed to prepare scatter read at 0x" << std::hex << address << std::dec << ".\n";
        return false;
    }
    return true;
}

bool PROCESS::add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (!VMMDLL_Scatter_PrepareWrite(scatter_handle, address, static_cast<PBYTE>(buffer), size)) {
        std::cerr << "[PROCESS] Failed to prepare scatter write at 0x" << std::hex << address << std::dec << ".\n";
        return false;
    }
    return true;
}

bool PROCESS::execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const {
    bool success = true;

    if (!VMMDLL_Scatter_Execute(scatter_handle)) {
        std::cerr << "[PROCESS] Failed to execute scatter." << "\n";
        success = false;
    }

    if (!VMMDLL_Scatter_Clear(scatter_handle, this->pid, VMMDLL_FLAG_NOCACHE)) {
        std::cerr << "[PROCESS] Failed to clear scatter." << "\n";
        success = false;
    }

    return success;
}

uint64_t cbSize = 0x80000;
VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo) {
    if (strcmp(uszName, "dtb.txt") == 0)
        cbSize = cb;
}

struct Info {
    uint32_t index;
    uint32_t process_id;
    uint64_t dtb;
    uint64_t kernelAddr;
    std::string name;
};

bool PROCESS::fix_cr3(const std::string& process_name) {
    PVMMDLL_MAP_MODULEENTRY module_entry;

    bool result = VMMDLL_Map_GetModuleFromNameU(handle, pid, process_name.c_str(), &module_entry, NULL);
    if (result) {
        return true;
    }

    if (!VMMDLL_InitializePlugins(handle)) {
        std::cerr << "[PROCESS] Failed to initialize plugins.\n";
        return false;
    }

    Sleep(500);

    while (true) {
        BYTE bytes[4] = { 0 };
        DWORD i = 0;
        auto nt = VMMDLL_VfsReadW(handle, (LPWSTR)L"\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);
        if (nt == VMMDLL_STATUS_SUCCESS && atoi((LPSTR)bytes) == 100)
            break;
        Sleep(100);
    }

    VMMDLL_VFS_FILELIST2 VfsFileList;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    VfsFileList.h = 0;
    VfsFileList.pfnAddDirectory = nullptr;
    VfsFileList.pfnAddFile = cbAddFile;

    result = VMMDLL_VfsListU(handle, (LPSTR)"\\misc\\procinfo\\", &VfsFileList);
    if (!result)
        return false;

    const size_t buffer_size = cbSize;
    std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
    DWORD j = 0;
    auto nt = VMMDLL_VfsReadW(handle, (LPWSTR)L"\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
    if (nt != VMMDLL_STATUS_SUCCESS)
        return false;

    std::vector<uint64_t> possible_dtbs;
    std::string lines(reinterpret_cast<char*>(bytes.get()));
    std::istringstream iss(lines);
    std::string line;

    while (std::getline(iss, line)) {
        Info info = {};
        std::istringstream info_ss(line);
        if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernelAddr >> info.name) {
            if (info.process_id == 0 || process_name.find(info.name) != std::string::npos) {
                possible_dtbs.push_back(info.dtb);
            }
        }
    }

    for (size_t i = 0; i < possible_dtbs.size(); i++) {
        auto dtb = possible_dtbs[i];
        VMMDLL_ConfigSet(handle, VMMDLL_OPT_PROCESS_DTB | pid, dtb);
        result = VMMDLL_Map_GetModuleFromNameU(handle, pid, process_name.c_str(), &module_entry, NULL);
        if (result) {
            static ULONG64 pml4_first[512];
            static ULONG64 pml4_second[512];
            DWORD readsize;

            if (!VMMDLL_MemReadEx(handle, -1, dtb, reinterpret_cast<PBYTE>(pml4_first), sizeof(pml4_first), &readsize,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
#ifdef _DEBUG
                std::cerr << "[PROCESS] Failed to read PML4 the first time.\n";
#endif
                return false;
            }

            if (!VMMDLL_MemReadEx(handle, -1, dtb, reinterpret_cast<PBYTE>(pml4_second), sizeof(pml4_second), &readsize,
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
            VMMDLL_ConfigSet(handle, VMMDLL_OPT_PROCESS_DTB | pid, 666);

            return true;
        }
    }

    std::cerr << "[PROCESS] Failed to patch process: " << process_name << ".\n";
    return false;
}