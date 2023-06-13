// Copyright 2023 Lars-Christian Schulz
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


namespace Pan {

/// \brief Wrapper for Cgo handles. Manages the lifetime of the contained handle.
/// GoHandle cannot be copied, use duplicate() to create a new unique duplicate
/// handle.
class GoHandle
{
public:
    static constexpr std::uintptr_t INVALID_HANDLE = 0;

    /// \brief Construct an invalid handle.
    constexpr GoHandle() : handle() { }

    /// \brief Take ownership of a handle.
    constexpr explicit GoHandle(std::uintptr_t h)
        : handle(h)
    {}

    GoHandle(const GoHandle &other);
    GoHandle(GoHandle &&other)
    {
        swap(*this, other);
    }

    GoHandle& operator=(const GoHandle &other);
    GoHandle& operator=(GoHandle &&other)
    {
        swap(*this, other);
        return *this;
    }

    ~GoHandle() { reset(); }

    /// \brief Initialize with a duplicate of the given handle.
    static GoHandle Duplicate(std::uintptr_t handle);

    /// \brief Duplicate the contained handle.
    GoHandle duplicate()
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
    operator bool() const { return handle != INVALID_HANDLE; }

    /// \brief Check whether the handle is not `PAN_INVALID_HANDLE`.
    bool isValid() const { return handle != INVALID_HANDLE; }

    /// \brief Get the contained handle.
    std::uintptr_t get() const noexcept { return handle; }

    /// \brief Get a pointer to the contained handle.
    /// \return Const pointer to contained handle.
    const std::uintptr_t *const getAddressOf() const { return &handle; }

    /// \brief Release the old handle and return the address of the contained
    /// handle for assignment of a new value.
    /// \return Mutable pointer to contained handle.
    std::uintptr_t* resetAndGetAddressOf()
    {
        reset();
        return &handle;
    }

    /// \brief Delete the owned handle and assign a new one.
    void reset(std::uintptr_t newHandle)
    {
        reset();
        handle = newHandle;
    }

    /// \brief Delete the owned handle.
    void reset();

    /// \brief Release ownership of the handle and return it.
    std::uintptr_t release() noexcept
    {
        std::uintptr_t tmp = handle;
        handle = INVALID_HANDLE;
        return tmp;

    }

    friend void swap(GoHandle &a, GoHandle &b)
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
        return reinterpret_cast<size_t>(handle.get());
    }
};
}
