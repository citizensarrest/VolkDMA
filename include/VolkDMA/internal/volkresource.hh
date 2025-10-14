#pragma once

extern "C" void VMMDLL_MemFree(void*);

template <class T>
class VolkResource {
public:
    VolkResource() = default;
    explicit VolkResource(T* p) : p_(p) {}
    ~VolkResource() { reset(); }

    VolkResource(const VolkResource&) = delete;
    VolkResource& operator=(const VolkResource&) = delete;

    VolkResource(VolkResource&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    VolkResource& operator=(VolkResource&& o) noexcept {
        if (this != &o) { reset(); p_ = o.p_; o.p_ = nullptr; }
        return *this;
    }

    T** out() { reset(); return &p_; }
    T* get() const { return p_; }
    T& operator*() const { return *p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
    void reset(T* np = nullptr) {
        if (p_) VMMDLL_MemFree(p_);
        p_ = np;
    }
    T* release() { T* r = p_; p_ = nullptr; return r; }

private:
    T* p_ = nullptr;
};