#include "inputstate.hh"

INPUTSTATE::INPUTSTATE(DMA& dma) : dma(dma) {
    std::string windows_version_string = this->query_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild", RegistryType::sz);
    if (windows_version_string.empty()) {
        std::cerr << "[INPUTSTATE] Failed to retrieve Windows version from registry.\n";
        return;
    }

    DWORD windows_version = std::stoi(windows_version_string);
    std::cout << "[INPUTSTATE] Windows version: " << windows_version << "\n";

    this->windows_logon_process_id = this->dma.get_process_id("winlogon.exe");
    if (!this->windows_logon_process_id) {
        std::cerr << "[INPUTSTATE] Failed to get process ID for winlogon.exe.\n";
        return;
    }
    std::cout << "[INPUTSTATE] Winlogon.exe process ID: " << this->windows_logon_process_id << "\n";

    std::vector<DWORD> csrss_ids = this->dma.get_process_id_list("csrss.exe");

    for (DWORD pid : csrss_ids) {
        PVMMDLL_MAP_EAT eat_map = nullptr;
        bool result = VMMDLL_Map_GetEATU(this->dma.handle, pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), &eat_map);

        if (!result || !eat_map) {
            std::cerr << "[INPUTSTATE] Failed to get EAT for PID " << pid << "\n";
            continue;
        }

        if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
            std::cerr << "[INPUTSTATE] EAT version mismatch for PID " << pid << ": got " << eat_map->dwVersion << "\n";
            VMMDLL_MemFree(eat_map);
            continue;
        }

        bool found = false;
        for (DWORD i = 0; i < eat_map->cMap; ++i) {
            auto& entry = eat_map->pMap[i];
            if (entry.uszFunction) {
                std::string func_name = entry.uszFunction;
                if (func_name == "gptCursorAsync") {
                    std::cout << "[INPUTSTATE] Found gptCursorAsync export at VA: 0x" << std::hex << entry.vaFunction << std::dec << "\n";
                    CURSOR position = dma.read<CURSOR>(entry.vaFunction, pid);
                    std::cout << "[INPUTSTATE] Mouse Position - X: " << position.x << ", Y: " << position.y << "\n";

                    found = true;
                    break;
                }
            }
        }

        VMMDLL_MemFree(eat_map);
    }

    if (windows_version > 22000) {
        if (csrss_ids.empty()) {
            std::cerr << "[INPUTSTATE] No csrss.exe processes found.\n";
        }
        else {
            std::cout << "[INPUTSTATE] Found " << csrss_ids.size() << " csrss.exe processes.\n";
        }

        for (DWORD process_id : csrss_ids) {
            std::cout << "[INPUTSTATE] Processing csrss.exe with PID: " << process_id << "\n";

            PVMMDLL_MAP_MODULEENTRY win32k_module_info;
            if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32ksgd.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32k.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                    std::cerr << "[INPUTSTATE] Failed to find win32ksgd.sys or win32k.sys for process " << process_id << "\n";
                    continue;
                }
            }
            uint64_t win32k_base = win32k_module_info->vaBase;
            uint64_t win32k_end = win32k_base + win32k_module_info->cbImageSize;
            std::cout << "[INPUTSTATE] Win32k module base: 0x" << std::hex << win32k_base << ", end: 0x" << win32k_end << std::dec << "\n";

            uint64_t gsession_ptr = this->dma.find_signature("48 8B 05 ? ? ? ? 48 8B 04 C8", win32k_base, win32k_end, process_id);
            if (!gsession_ptr)
                gsession_ptr = this->dma.find_signature("48 8B 05 ? ? ? ? FF C9", win32k_base, win32k_end, process_id);
            if (!gsession_ptr) {
                std::cerr << "[INPUTSTATE] Failed to find signature in win32k for process " << process_id << "\n";
                continue;
            }
            std::cout << "[INPUTSTATE] Found signature at 0x" << std::hex << gsession_ptr << std::dec << " in process " << process_id << "\n";

            int relative = this->dma.read<int>(gsession_ptr + 3, process_id);
            uint64_t g_session_global_slots = gsession_ptr + 7 + relative;
            std::cout << "[INPUTSTATE] Calculated g_session_global_slots: 0x" << std::hex << g_session_global_slots << std::dec << "\n";

            uint64_t user_session_state = 0;
            for (int i = 0; i < 4; i++) {
                user_session_state = this->dma.read<uint64_t>(this->dma.read<uint64_t>(this->dma.read<uint64_t>(g_session_global_slots, process_id) + 8 * i, process_id), process_id);
                std::cout << "[INPUTSTATE] Iteration " << i << " - user_session_state: 0x" << std::hex << user_session_state << std::dec << "\n";
                if (user_session_state > 0x7FFFFFFFFFFF)
                    break;
            }
            std::cout << "[INPUTSTATE] Final user_session_state: 0x" << std::hex << user_session_state << std::dec << "\n";

            PVMMDLL_MAP_MODULEENTRY win32kbase_info;
            if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32kbase.sys"), &win32kbase_info, VMMDLL_MODULE_FLAG_NORMAL)) {
                std::cerr << "[INPUTSTATE] Failed to find win32kbase.sys for process " << process_id << "\n";
                continue;
            }
            uint64_t win32kbase_base = win32kbase_info->vaBase;
            uint64_t win32kbase_end = win32kbase_base + win32kbase_info->cbImageSize;
            std::cout << "[INPUTSTATE] Win32kbase module base: 0x" << std::hex << win32kbase_base << ", end: 0x" << win32kbase_end << std::dec << "\n";

            uint64_t sig_ptr = this->dma.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_base, win32kbase_end, process_id);
            if (!sig_ptr) {
                std::cerr << "[INPUTSTATE] Failed to find signature in win32kbase.sys for process " << process_id << "\n";
                continue;
            }
            std::cout << "[INPUTSTATE] Found signature at 0x" << std::hex << sig_ptr << std::dec << " in win32kbase.sys for process " << process_id << "\n";

            uint32_t session_offset = this->dma.read<uint32_t>(sig_ptr + 3, process_id);
            this->async_key_state = user_session_state + session_offset;
            std::cout << "[INPUTSTATE] Calculated async_key_state: 0x" << std::hex << this->async_key_state << std::dec << "\n";

            if (this->async_key_state > 0x7FFFFFFFFFFF) {
                std::cout << "[INPUTSTATE] Valid async_key_state found, breaking loop.\n";
                break;
            }
        }
    }
    else {
        PVMMDLL_MAP_EAT eat_map = NULL;
        PVMMDLL_MAP_EATENTRY eat_map_entry = NULL;

        std::cout << "[INPUTSTATE] Retrieving EAT map for win32kbase.sys in winlogon.exe PID: " << this->windows_logon_process_id << "\n";
        bool result = VMMDLL_Map_GetEATU(this->dma.handle, this->windows_logon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), &eat_map);

        if (!result || eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
            if (eat_map) VMMDLL_MemFree(eat_map);
            std::cerr << "[INPUTSTATE] Failed to retrieve EAT map for win32kbase.sys.\n";
            return;
        }
        std::cout << "[INPUTSTATE] Successfully retrieved EAT map with " << eat_map->cMap << " entries.\n";

        for (int i = 0; i < eat_map->cMap; i++) {
            eat_map_entry = eat_map->pMap + i;
            if (strcmp(eat_map_entry->uszFunction, "gafAsyncKeyState") == 0) {
                this->async_key_state = eat_map_entry->vaFunction;
                std::cout << "[INPUTSTATE] Found gafAsyncKeyState at 0x" << std::hex << this->async_key_state << std::dec << "\n";
                break;
            }
        }
        VMMDLL_MemFree(eat_map);
    }

    if (this->async_key_state <= 0x7FFFFFFFFFFF) {
        std::cerr << "[INPUTSTATE] Failed to initialize. Windows version: " << windows_version
            << ", Async key state: 0x" << std::hex << this->async_key_state << std::dec
            << ". Possible causes: signature not found or invalid EAT entry.\n";
    }
    else {
        std::cout << "[INPUTSTATE] Successfully initialized with async_key_state: 0x" << std::hex << this->async_key_state << std::dec << "\n";
    }
}

CURSOR INPUTSTATE::get_cursor_position() {
    return this->dma.read<CURSOR>(this->async_cursor, this->cursor_process_id);
}

void INPUTSTATE::read_bitmap() {
	VMMDLL_MemReadEx(this->dma.handle, this->windows_logon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, this->async_key_state, reinterpret_cast<PBYTE>(&this->state_bitmap), sizeof(this->state_bitmap), NULL, VMMDLL_FLAG_NOCACHE);
}

bool INPUTSTATE::is_key_down(uint32_t virtual_key_code) {
	if (virtual_key_code >= 256) return false;

	int byte_index = (virtual_key_code * 2) / 8;
	int bit_offset = (virtual_key_code * 2) % 8;

	return (this->state_bitmap[byte_index] & (1 << bit_offset)) != 0;
}

void INPUTSTATE::print_down_keys() {
	for (const auto& [vk_code, key_name] : INPUTSTATE::inputs) {
		int byte_index = (vk_code * 2) / 8;
		int bit_offset = (vk_code * 2) % 8;

		if (this->state_bitmap[byte_index] & (1 << bit_offset)) {
			printf("Key: %s is down\n", key_name.data());
		}
	}
}

std::string INPUTSTATE::query_registry_value(const char* path, RegistryType type) {
	BYTE rdbuf[1024] = { };
	DWORD rdbuf_size = sizeof(rdbuf);
	DWORD* reg_type = reinterpret_cast<LPDWORD>(&type);

	if (!VMMDLL_WinReg_QueryValueExU(this->dma.handle, path, reg_type, rdbuf, &rdbuf_size)) {
		return "";
	}

	if (type == RegistryType::dword) {
		return std::to_string(*reinterpret_cast<DWORD*>(rdbuf));
	}

	std::wstring wstr = std::wstring(reinterpret_cast<wchar_t*>(rdbuf));

	return std::string(wstr.begin(), wstr.end());
}