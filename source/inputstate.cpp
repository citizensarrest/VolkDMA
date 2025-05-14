#include "inputstate.hh"

INPUTSTATE::INPUTSTATE(DMA& dma) : dma(dma) {
	std::string windows_version_string = this->query_registry_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild", RegistryType::sz);
    if (windows_version_string.empty()) {
        std::cerr << "[INPUTSTATE] Failed to retrieve Windows version from registry.\n";
        return;
    }

    DWORD windows_version = std::stoi(windows_version_string);

	this->windows_logon_process_id = this->dma.get_process_id("winlogon.exe");
    if (!this->windows_logon_process_id) {
        std::cerr << "[INPUTSTATE] Failed to get process ID for winlogon.exe.\n";
        return;
    }

	if (windows_version > 22000) {
		std::vector<DWORD> process_ids = this->dma.get_process_id_list("csrss.exe");
        if (process_ids.empty()) {
            std::cerr << "[INPUTSTATE] No csrss.exe processes found.\n";
        }

		for (DWORD process_id : process_ids) {
			PVMMDLL_MAP_MODULEENTRY win32k_module_info;
			if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32ksgd.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
				if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32k.sys"), &win32k_module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
					continue;
				}
			}
			uint64_t win32k_base = win32k_module_info->vaBase;
			uint64_t win32k_end = win32k_base + win32k_module_info->cbImageSize;

			uint64_t gsession_ptr = this->dma.find_signature("48 8B 05 ? ? ? ? 48 8B 04 C8", win32k_base, win32k_end, process_id);
			if (!gsession_ptr)
				gsession_ptr = this->dma.find_signature("48 8B 05 ? ? ? ? FF C9", win32k_base, win32k_end, process_id);
			if (!gsession_ptr) continue;

			int relative = this->dma.read<int>(gsession_ptr + 3, process_id);
			uint64_t g_session_global_slots = gsession_ptr + 7 + relative;

			uint64_t user_session_state = 0;
			for (int i = 0; i < 4; i++) {
				user_session_state = this->dma.read<uint64_t>(this->dma.read<uint64_t>(this->dma.read<uint64_t>(g_session_global_slots, process_id) + 8 * i, process_id), process_id);
				if (user_session_state > 0x7FFFFFFFFFFF)
					break;
			}

			PVMMDLL_MAP_MODULEENTRY win32kbase_info;
			if (!VMMDLL_Map_GetModuleFromNameW(this->dma.handle, process_id, const_cast<LPWSTR>(L"win32kbase.sys"), &win32kbase_info, VMMDLL_MODULE_FLAG_NORMAL)) {
				continue;
			}
			uint64_t win32kbase_base = win32kbase_info->vaBase;
			uint64_t win32kbase_end = win32kbase_base + win32kbase_info->cbImageSize;

			uint64_t sig_ptr = this->dma.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_base, win32kbase_end, process_id);
			if (!sig_ptr) continue;

			uint32_t session_offset = this->dma.read<uint32_t>(sig_ptr + 3, process_id);
			this->async_key_state = user_session_state + session_offset;

			if (this->async_key_state > 0x7FFFFFFFFFFF)
				break;
		}
	}
	else {
		PVMMDLL_MAP_EAT eat_map = NULL;
		PVMMDLL_MAP_EATENTRY eat_map_entry = NULL;

		bool result = VMMDLL_Map_GetEATU(this->dma.handle, this->dma.get_process_id("winlogon.exe") | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), &eat_map);

		if (!result || eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
			if (eat_map) VMMDLL_MemFree(eat_map);
			return;
		}

		for (int i = 0; i < eat_map->cMap; i++) {
			eat_map_entry = eat_map->pMap + i;
			if (strcmp(eat_map_entry->uszFunction, "gafAsyncKeyState") == 0) {
				this->async_key_state = eat_map_entry->vaFunction;
				break;
			}
		}
		VMMDLL_MemFree(eat_map);
	}

    if (this->async_key_state <= 0x7FFFFFFFFFFF) {
        std::cerr << "[INPUTSTATE] Failed to initialize. Windows version: " << windows_version
            << ", Async key state: 0x" << std::hex << this->async_key_state << std::dec << "\n";
    }
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
			printf("Key: %s is down\n", key_name.c_str());
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