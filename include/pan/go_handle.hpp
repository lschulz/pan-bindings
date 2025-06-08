// Copyright 2023-2024 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdint>
#include <functional>

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

namespace Pan {

/// \brief Wrapper for Cgo handles. Manages the lifetime of the contained handle.
/// \details GoHandle cannot be copied, use duplicate() to create a new unique
/// duplicate handle.
class GoHandle
{
public:
    static constexpr std::uintptr_t INVALID_HANDLE = 0;

    /// \brief Construct an invalid handle.
    constexpr GoHandle() noexcept : handle() { }

    /// \brief Take ownership of a handle.
    constexpr explicit GoHandle(std::uintptr_t h) noexcept
        : handle(h)
    {}

    DLLEXPORT
    GoHandle(const GoHandle &other) noexcept;
    GoHandle(GoHandle &&other) noexcept
    {
        swap(*this, other);
    }

    DLLEXPORT
    GoHandle& operator=(const GoHandle &other) noexcept;
    GoHandle& operator=(GoHandle &&other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    ~GoHandle() { reset(); }

    /// \brief Initialize with a duplicate of the given handle.
    DLLEXPORT
    static GoHandle Duplicate(std::uintptr_t handle) noexcept;

    /// \brief Duplicate the contained handle.
    GoHandle duplicate() noexcept
    {
        return GoHandle::Duplicate(handle);
    }

    bool operator==(const GoHandle &other) const
    { return handle == other.handle; }

    bool operator!=(const GoHandle &other) const
    { return handle != other.handle; }

    bool operator<(const GoHandle &other) const
    { return handle < other.handle; }

    bool operator<=(const GoHandle &other) const
    { return handle <= other.handle; }

    bool operator>(const GoHandle &other) const
    { return handle > other.handle; }

    bool operator>=(const GoHandle &other) const
    { return handle >= other.handle; }

    /// \brief Check whether the handle is not `PAN_INVALID_HANDLE`.
    operator bool() const noexcept { return handle != INVALID_HANDLE; }

    /// \brief Check whether the handle is not `PAN_INVALID_HANDLE`.
    bool isValid() const noexcept { return handle != INVALID_HANDLE; }

    /// \brief Get the contained handle.
    std::uintptr_t get() const noexcept { return handle; }

    /// \brief Get a pointer to the contained handle.
    /// \return Const pointer to contained handle.
    const std::uintptr_t *const getAddressOf() const noexcept { return &handle; }

    /// \brief Release the old handle and return the address of the contained
    /// handle for assignment of a new value.
    /// \return Mutable pointer to contained handle.
    std::uintptr_t* resetAndGetAddressOf() noexcept
    {
        reset();
        return &handle;
    }

    /// \brief Delete the owned handle and assign a new one.
    void reset(std::uintptr_t newHandle) noexcept
    {
        reset();
        handle = newHandle;
    }

    /// \brief Delete the owned handle.
    DLLEXPORT
    void reset() noexcept;

    /// \brief Release ownership of the handle and return it.
    std::uintptr_t release() noexcept
    {
        std::uintptr_t tmp = handle;
        handle = INVALID_HANDLE;
        return tmp;

    }

    friend void swap(GoHandle &a, GoHandle &b) noexcept
    {
        std::swap(a.handle, b.handle);
    }

private:
    std::uintptr_t handle = INVALID_HANDLE;
};

} // namespace Pan


namespace std
{
template <>
struct hash<Pan::GoHandle>
{
    size_t operator()(const Pan::GoHandle&handle) const
    {
        return static_cast<size_t>(handle.get());
    }
};
}
