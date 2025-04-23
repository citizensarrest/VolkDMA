#pragma once

#include <unordered_map>
#include "dma.hh"

class INPUTSTATE {
public:
	INPUTSTATE(DMA& dma);
	void read_bitmap();
	bool is_key_down(uint32_t virtual_key_code);
	void print_down_keys();

private:
	DMA& dma;
	
	DWORD windows_logon_process_id = 0;
	uint64_t async_key_state = 0;
	uint8_t state_bitmap[64] = {};

	static const std::unordered_map<int, std::string> inputs;

	enum class RegistryType {
		sz = REG_SZ,
		dword = REG_DWORD,
	};

	std::string query_registry_value(const char* path, RegistryType type);
};