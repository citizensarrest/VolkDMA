#include "inputstate.hh"

const std::unordered_map<int, std::string> INPUTSTATE::inputs = {
    {0x01, "Left Mouse Button"},
    {0x02, "Right Mouse Button"},
    {0x03, "Control-break Processing"},
    {0x04, "Middle Mouse Button"},
    {0x05, "X1 Mouse Button"},
    {0x06, "X2 Mouse Button"},
    {0x08, "Backspace"},
    {0x09, "Tab"},
    {0x0C, "Clear"},
    {0x0D, "Enter"},
    {0x10, "Shift"},
    {0x11, "Control"},
    {0x12, "Alt"},
    {0x13, "Pause"},
    {0x14, "Caps Lock"},
    {0x15, "IME Kana/Hangul"},
    {0x16, "IME On"},
    {0x17, "IME Junja"},
    {0x18, "IME Final"},
    {0x19, "IME Hanja/Kanji"},
    {0x1A, "IME Off"},
    {0x1B, "Escape"},
    {0x1C, "IME Convert"},
    {0x1D, "IME Nonconvert"},
    {0x1E, "IME Accept"},
    {0x1F, "IME Mode Change"},
    {0x20, "Spacebar"},
    {0x21, "Page Up"},
    {0x22, "Page Down"},
    {0x23, "End"},
    {0x24, "Home"},
    {0x25, "Left Arrow"},
    {0x26, "Up Arrow"},
    {0x27, "Right Arrow"},
    {0x28, "Down Arrow"},
    {0x29, "Select"},
    {0x2A, "Print"},
    {0x2B, "Execute"},
    {0x2C, "Print Screen"},
    {0x2D, "Insert"},
    {0x2E, "Delete"},
    {0x2F, "Help"},
    {0x30, "0"},
    {0x31, "1"},
    {0x32, "2"},
    {0x33, "3"},
    {0x34, "4"},
    {0x35, "5"},
    {0x36, "6"},
    {0x37, "7"},
    {0x38, "8"},
    {0x39, "9"},
    {0x41, "A"},
    {0x42, "B"},
    {0x43, "C"},
    {0x44, "D"},
    {0x45, "E"},
    {0x46, "F"},
    {0x47, "G"},
    {0x48, "H"},
    {0x49, "I"},
    {0x4A, "J"},
    {0x4B, "K"},
    {0x4C, "L"},
    {0x4D, "M"},
    {0x4E, "N"},
    {0x4F, "O"},
    {0x50, "P"},
    {0x51, "Q"},
    {0x52, "R"},
    {0x53, "S"},
    {0x54, "T"},
    {0x55, "U"},
    {0x56, "V"},
    {0x57, "W"},
    {0x58, "X"},
    {0x59, "Y"},
    {0x5A, "Z"},
    {0x5B, "Left Windows"},
    {0x5C, "Right Windows"},
    {0x5D, "Applications"},
    {0x5F, "Sleep"},
    {0x60, "Numpad 0"},
    {0x61, "Numpad 1"},
    {0x62, "Numpad 2"},
    {0x63, "Numpad 3"},
    {0x64, "Numpad 4"},
    {0x65, "Numpad 5"},
    {0x66, "Numpad 6"},
    {0x67, "Numpad 7"},
    {0x68, "Numpad 8"},
    {0x69, "Numpad 9"},
    {0x6A, "Numpad *"},
    {0x6B, "Numpad +"},
    {0x6C, "Numpad Separator"},
    {0x6D, "Numpad -"},
    {0x6E, "Numpad ."},
    {0x6F, "Numpad /"},
    {0x70, "F1"},
    {0x71, "F2"},
    {0x72, "F3"},
    {0x73, "F4"},
    {0x74, "F5"},
    {0x75, "F6"},
    {0x76, "F7"},
    {0x77, "F8"},
    {0x78, "F9"},
    {0x79, "F10"},
    {0x7A, "F11"},
    {0x7B, "F12"},
    {0x7C, "F13"},
    {0x7D, "F14"},
    {0x7E, "F15"},
    {0x7F, "F16"},
    {0x80, "F17"},
    {0x81, "F18"},
    {0x82, "F19"},
    {0x83, "F20"},
    {0x84, "F21"},
    {0x85, "F22"},
    {0x86, "F23"},
    {0x87, "F24"},
    {0x90, "Num Lock"},
    {0x91, "Scroll Lock"},
    {0xA0, "Left Shift"},
    {0xA1, "Right Shift"},
    {0xA2, "Left Control"},
    {0xA3, "Right Control"},
    {0xA4, "Left Alt"},
    {0xA5, "Right Alt"},
    {0xA6, "Browser Back"},
    {0xA7, "Browser Forward"},
    {0xA8, "Browser Refresh"},
    {0xA9, "Browser Stop"},
    {0xAA, "Browser Search"},
    {0xAB, "Browser Favorites"},
    {0xAC, "Browser Home"},
    {0xAD, "Volume Mute"},
    {0xAE, "Volume Down"},
    {0xAF, "Volume Up"},
    {0xB0, "Next Track"},
    {0xB1, "Previous Track"},
    {0xB2, "Stop Media"},
    {0xB3, "Play/Pause"},
    {0xBA, "Semicolon"},
    {0xBB, "Equals"},
    {0xBC, "Comma"},
    {0xBD, "Minus"},
    {0xBE, "Period"},
    {0xBF, "Forward Slash"},
    {0xC0, "Grave Accent"},
    {0xDB, "Left Bracket"},
    {0xDC, "Backslash"},
    {0xDD, "Right Bracket"},
    {0xDE, "Single Quote"},
    {0xFF, "System Quirk (often Pause or Print Screen)"},
};

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

    if (this->async_key_state == 0 || this->async_key_state > 0x7FFFFFFFFFFF) {
        std::cerr << "[INPUTSTATE] Failed to initialize. Windows version: " << windows_version << "\n";
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
    for (int virtual_key_code = 0; virtual_key_code < 256; virtual_key_code++) {
        int byte_index = (virtual_key_code * 2) / 8;
        int bit_offset = (virtual_key_code * 2) % 8;

        if (this->state_bitmap[byte_index] & (1 << bit_offset)) {
            auto it = INPUTSTATE::inputs.find(virtual_key_code);
            if (it != INPUTSTATE::inputs.end()) {
                printf("Key: %s is down\n", it->second.c_str());
            }
            else {
                printf("Key: Unknown Key (0x%02X) is down\n", virtual_key_code);
            }
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