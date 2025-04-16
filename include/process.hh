#pragma once

#include "vmmdll.h"

#include <string>
#include <vector>

class PROCESS {
public:
    PROCESS(VMM_HANDLE handle, const std::string& process_name);

    uintptr_t get_base_address(const std::string& module_name) const;

    bool fix_cr3(const std::string& process_name);

    bool read(uintptr_t address, void* buffer, size_t size) const;
    template <typename T>
    T read(uintptr_t address) const {
        T buffer{};
        read(address, &buffer, sizeof(T));
        return buffer;
    }

    uint64_t read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
        uint64_t result = read<uint64_t>(base + offsets.at(0));
        for (size_t i = 1; i < offsets.size(); ++i) {
            result = read<uint64_t>(result + offsets.at(i));
        }
        return result;
    }

    template <typename T>
    T read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
        uint64_t result = read<uint64_t>(base + offsets.at(0));
        for (size_t i = 1; i < offsets.size() - 1; ++i) {
            result = read<uint64_t>(result + offsets.at(i));
        }
        return read<T>(result + offsets.back());
    }

    bool write(uintptr_t address, void* buffer, size_t size) const;
    template <typename T>
    void write(uintptr_t address, T value) const {
        write(address, &value, sizeof(T));
    }

    VMMDLL_SCATTER_HANDLE create_scatter() const;
    void close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const;

    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    template <typename T>
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, T* buffer) const {
        return add_read_scatter(scatter_handle, address, reinterpret_cast<void*>(buffer), sizeof(T));
    }

    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    template <typename T>
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, const T& value) const {
        return add_write_scatter(scatter_handle, address, reinterpret_cast<void*>(const_cast<T*>(&value)), sizeof(T));
    }

    bool execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const;

    int get_pid() const {
        return pid;
    }

private:
    VMM_HANDLE handle;
    int pid;
};