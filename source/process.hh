#pragma once

#include <unordered_map>
#include "dma.hh"

class Process {
public:
    Process(DMA& dma, const std::string& process_name);
    [[nodiscard]] uint64_t get_base_address(const std::string& module_name) const;
    [[nodiscard]] size_t get_size(const std::string& module_name) const;
    bool dump_module(const std::string& module_name, const std::string& path) const;
    [[nodiscard]] std::string get_path(const std::string& module_name) const;
    [[nodiscard]] std::vector<std::string> get_modules(DWORD process_id = 0) const;
    bool fix_cr3(const std::string& process_name);
    [[nodiscard]] inline constexpr bool is_valid_address(const uint64_t address) const { return address >= minimum_valid_address; }
    bool virtual_to_physical(uint64_t virtual_address, uint64_t& physical_address) const;
    bool read(uint64_t address, void* buffer, size_t size) const;
    [[nodiscard]] uint64_t read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const;
    bool write(uint64_t address, void* buffer, size_t size, DWORD process_id = 0) const;
    [[nodiscard]] VMMDLL_SCATTER_HANDLE create_scatter(DWORD process_id = 0) const;
    void close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const;
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, DWORD process_id = 0) const;

    template <typename T>
    [[nodiscard]] T read(uint64_t address) const {
        T buffer{};
        this->read(address, &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    [[nodiscard]] T read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
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
    const DMA& dma;
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

    inline static uint64_t cb_size = 0x80000;
    static VOID cb_add_file(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
};