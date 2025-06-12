#include "inputstate.hh"

InputState::InputState(const DMA& dma) : dma_(dma) {
    const std::vector<DWORD> csrss_process_ids = dma_.get_process_id_list("csrss.exe");

    if (retrieve_gptCursorAsync(csrss_process_ids)) {
        std::cout << "[INPUTSTATE] Successfully retrieved gptCursorAsync!\n";
    }
    else {
        std::cerr << "[INPUTSTATE] Failed to retrieve gptCursorAsync!\n";
    }

    if (!VMMDLL_ConfigGet(dma_.handle, VMMDLL_OPT_WIN_VERSION_BUILD, &windows_version_build_)) {
        std::cerr << "[INPUTSTATE] Failed to retrieve Windows build!\n";
        return;
    }

    if (retrieve_gafAsyncKeyState(csrss_process_ids)) {
        std::cout << "[INPUTSTATE] Successfully retrieved gafAsyncKeyState!\n";
    }
    else {
        std::cerr << "[INPUTSTATE] Failed to retrieve gafAsyncKeyState!\n";
    }
}

[[nodiscard]] bool InputState::retrieve_gafAsyncKeyState(const std::vector<DWORD>& csrss_process_ids) {
    winlogon_process_id_ = dma_.get_process_id("winlogon.exe");
    if (!winlogon_process_id_) {
        std::cerr << "[INPUTSTATE] Failed to get process ID for winlogon.exe.\n";
        return false;
    }

    if (windows_version_build_ > 22000) {
        if (csrss_process_ids.empty()) {
            std::cerr << "[INPUTSTATE] No csrss.exe processes found.\n";
            return false;
        }

        for (const DWORD& process_id : csrss_process_ids) {
            PVMMDLL_MAP_MODULEENTRY win32k_module_info = nullptr;
            std::string_view win32k_module_name;
            if (VMMDLL_Map_GetModuleFromNameW(dma_.handle, process_id, const_cast<LPWSTR>(L"win32ksgd.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                win32k_module_name = "win32ksgd.sys";
            }
            else if (VMMDLL_Map_GetModuleFromNameW(dma_.handle, process_id, const_cast<LPWSTR>(L"win32k.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                win32k_module_name = "win32k.sys";
            }
            else {
                std::cerr << "[INPUTSTATE] Failed to find win32ksgd.sys or win32k.sys for csrss.exe with process ID: " << process_id << "\n";
                continue;
            }

            uint64_t g_session_address = dma_.find_signature("48 8B 05 ? ? ? ? 48 8B 04 C8", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize, process_id);
            if (!g_session_address)
                g_session_address = dma_.find_signature("48 8B 05 ? ? ? ? FF C9", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize, process_id);
            
            if (!g_session_address) {
                std::cerr << "[INPUTSTATE] Failed to find signature in " << win32k_module_name << " for csrss.exe with process ID: " << process_id << "\n";
                continue;
            }

            uint64_t user_session_state = 0;
            for (int i = 0; i < 4; i++) {
                user_session_state = dma_.read<uint64_t>(dma_.read<uint64_t>(dma_.read<uint64_t>(g_session_address + 7 + dma_.read<int>(g_session_address + 3, process_id), process_id) + 8 * i, process_id), process_id);
                if (user_session_state > 0x7FFFFFFFFFFF)
                    break;
            }

            PVMMDLL_MAP_MODULEENTRY win32kbase_info = nullptr;
            if (!VMMDLL_Map_GetModuleFromNameW(dma_.handle, process_id, const_cast<LPWSTR>(L"win32kbase.sys"), &win32kbase_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                std::cerr << "[INPUTSTATE] Failed to find win32kbase.sys for csrss.exe with process ID: " << process_id << "\n";
                continue;
            }

            uint64_t sig_ptr = dma_.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_info->vaBase, win32kbase_info->vaBase + win32kbase_info->cbImageSize, process_id);
            if (!sig_ptr) {
                std::cerr << "[INPUTSTATE] Failed to find signature in win32kbase.sys for csrss.exe with process ID: " << process_id << "\n";
                continue;
            }

            gafAsyncKeyState_address_ = user_session_state + dma_.read<uint32_t>(sig_ptr + 3, process_id);

            if (gafAsyncKeyState_address_ > 0x7FFFFFFFFFFF) {
                return true;
            }
        }

        return false;
    }

    // windows_version_build <= 22000
    PVMMDLL_MAP_EAT eat_map = nullptr;
    if (!VMMDLL_Map_GetEATU(dma_.handle, winlogon_process_id_ | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), &eat_map) || eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
        if (eat_map) VMMDLL_MemFree(eat_map);
        std::cerr << "[INPUTSTATE] Failed to retrieve EAT map in win32kbase.sys for winlogon.exe with process ID: " << winlogon_process_id_ << "\n";
        return false;
    }

    for (DWORD i = 0; i < eat_map->cMap; ++i) {
        PVMMDLL_MAP_EATENTRY entry = eat_map->pMap + i;
        if (strcmp(entry->uszFunction, "gafAsyncKeyState") == 0) {
            gafAsyncKeyState_address_ = entry->vaFunction;
            break;
        }
    }

    VMMDLL_MemFree(eat_map);
    return gafAsyncKeyState_address_ > 0x7FFFFFFFFFFF;
}

[[nodiscard]] bool InputState::retrieve_gptCursorAsync(const std::vector<DWORD>& csrss_process_ids) {
    if (csrss_process_ids.empty()) {
        std::cerr << "[INPUTSTATE] No csrss.exe processes found.\n";
        return false;
    }

    for (const DWORD& process_id : csrss_process_ids) {
        PVMMDLL_MAP_EAT eat_map = nullptr;
        if (!VMMDLL_Map_GetEATU(dma_.handle, process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), &eat_map)) {
            std::cerr << "[INPUTSTATE] Failed to retrieve EAT map in win32kbase.sys for csrss.exe with process ID: " << process_id << "\n";
            continue;
        }

        if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
            std::cerr << "[INPUTSTATE] EAT version mismatch for process ID " << process_id << ": got " << eat_map->dwVersion << "\n";
            VMMDLL_MemFree(eat_map);
            continue;
        }

        for (DWORD i = 0; i < eat_map->cMap; ++i) {
            auto& entry = eat_map->pMap[i];

            if (!entry.uszFunction)
                continue;

            std::string_view export_function_name(entry.uszFunction);
            if (export_function_name.find("gptCursorAsync") == std::string::npos)
                continue;

            POINT position = dma_.read<POINT>(entry.vaFunction, process_id);

            if (((position.x == 0 && position.y == 0) || (position.x == 512 && position.y == 384)))
                continue;

            gptCursorAsync_process_id_ = process_id;
            gptCursorAsync_address_ = entry.vaFunction;
            break;
        }

        VMMDLL_MemFree(eat_map);
    }

    return (gptCursorAsync_address_ != 0 && gptCursorAsync_process_id_ != 0);
}

[[nodiscard]] POINT InputState::get_cursor_position() const {
    return dma_.read<POINT>(gptCursorAsync_address_, gptCursorAsync_process_id_);
}

void InputState::read_bitmap() {
	VMMDLL_MemReadEx(dma_.handle, winlogon_process_id_ | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, gafAsyncKeyState_address_, reinterpret_cast<PBYTE>(&state_bitmap_), sizeof(state_bitmap_), nullptr, VMMDLL_FLAG_NOCACHE);
}

[[nodiscard]] bool InputState::is_key_down(uint8_t virtual_key_code) const {
    constexpr int bits_per_key = 2;
    constexpr int bits_per_byte = 8;

    const int bit_index = virtual_key_code * bits_per_key;
    const int byte_index = bit_index / bits_per_byte;
    const int bit_offset = bit_index % bits_per_byte;

    return (state_bitmap_[byte_index] & (1 << bit_offset)) != 0;
}

void InputState::print_down_keys() const {
    for (const auto& [code, name] : virtual_keys) {
        if (is_key_down(code)) {
            std::cout << "Key: " << name << " is down\n";
        }
    }
}