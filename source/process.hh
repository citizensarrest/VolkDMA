#pragma once

#include <unordered_map>
#include "dma.hh"

class PROCESS {
public:
    PROCESS(DMA& dma, const std::string& process_name);
    uint64_t get_base_address(const std::string& module_name) const;
    std::string get_path(const std::string& module_name) const;
    bool fix_cr3(const std::string& process_name);
    bool is_valid_address(uint64_t address) const;
    bool virtual_to_physical(uint64_t virtual_address, uint64_t& physical_address) const;
    bool read(uint64_t address, void* buffer, size_t size) const;
    uint64_t read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const;
    bool write(uint64_t address, void* buffer, size_t size, DWORD process_id = 0) const;
    VMMDLL_SCATTER_HANDLE create_scatter(DWORD process_id = 0) const;
    void close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const;
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, DWORD process_id = 0) const;

    template <typename T>
    T read(uint64_t address) const {
        T buffer{};
        this->read(address, &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    T read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
        uint64_t result = this->read<uint64_t>(base + offsets.at(0));
        for (size_t i = 1; i < offsets.size() - 1; ++i) {
            result = this->read<uint64_t>(result + offsets.at(i));
        }
        return this->read<T>(result + offsets.back());
    }

    template <typename T>
    void write(uint64_t address, T value, DWORD process_id = 0) const {
        this->write(address, &value, sizeof(T), process_id);
    }

    template <typename T>
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, T* buffer) const {
        return this->add_read_scatter(scatter_handle, address, reinterpret_cast<void*>(buffer), sizeof(T));
    }

    template <typename T>
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, const T& value) const {
        return this->add_write_scatter(scatter_handle, address, reinterpret_cast<void*>(const_cast<T*>(&value)), sizeof(T));
    }

private:
    DMA& dma;
    DWORD process_id;

    struct Info {
        uint32_t index;
        DWORD process_id;
        uint64_t dtb;
        uint64_t kernel_address;
        std::string name;
    };

    static constexpr uint64_t minimum_valid_address = 0x1000;

    static constexpr DWORD scatter_flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO;
    mutable std::unordered_map<VMMDLL_SCATTER_HANDLE, int> scatter_counts;

    static uint64_t cb_size;
    static VOID cb_add_file(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
};