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


// Note: No inline definitions of members here
// Otherwise bindgen wont find them to produce the rust bindings
namespace Pan {
    class GoHandle;
    void swap(GoHandle &a, GoHandle &b);

/// \brief Wrapper for Cgo handles. Manages the lifetime of the contained handle.
/// GoHandle cannot be copied, use duplicate() to create a new unique duplicate
/// handle.
class GoHandle
{
public:
    static constexpr std::uintptr_t INVALID_HANDLE = 0;

    /// \brief Construct an invalid handle.
    GoHandle();

    /// \brief Take ownership of a handle.
    explicit GoHandle(std::uintptr_t h);

    GoHandle(const GoHandle &other);
    GoHandle(GoHandle &&other);

    GoHandle& operator=(const GoHandle &other);
    GoHandle& operator=(GoHandle &&other);

    ~GoHandle();

    /// \brief Initialize with a duplicate of the given handle.
    static GoHandle Duplicate(std::uintptr_t handle);

    /// \brief Duplicate the contained handle.
    GoHandle duplicate();

    bool operator==(const GoHandle &other) const;

    bool operator!=(const GoHandle &other) const;

    bool operator<(const GoHandle &other) const
    { return handle < other.handle; }

    bool operator<=(const GoHandle &other) const
    { return handle <= other.handle; }

    bool operator>(const GoHandle &other) const
    { return handle > other.handle; }

    bool operator>=(const GoHandle &other) const
    { return handle >= other.handle; }

    /// \brief Check whether the handle is not `PAN_INVALID_HANDLE`.
    operator bool() const;

    /// \brief Check whether the handle is not `PAN_INVALID_HANDLE`.
    bool isValid() const;

    /// \brief Get the contained handle.
    std::uintptr_t get() const noexcept;

    /// \brief Get a pointer to the contained handle.
    /// \return Const pointer to contained handle.
    const std::uintptr_t *const getAddressOf() const;

    /// \brief Release the old handle and return the address of the contained
    /// handle for assignment of a new value.
    /// \return Mutable pointer to contained handle.
    std::uintptr_t* resetAndGetAddressOf();

    /// \brief Delete the owned handle and assign a new one.
    void reset(std::uintptr_t newHandle);

    /// \brief Delete the owned handle.
    void reset();

    /// \brief Release ownership of the handle and return it.
    std::uintptr_t release() noexcept;

    friend void swap(GoHandle &a, GoHandle &b);
private:
    std::uintptr_t handle = INVALID_HANDLE;
};

} // namespace Pan

#ifndef BUILDING_RUST
/*
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
*/
#endif