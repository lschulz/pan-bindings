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
#include <functional>
#include "pan/go_handle.hpp"
#include "pan/pan.h"

namespace Pan
{   
    bool GoHandle::operator!=(const GoHandle &other) const
    { return handle != other.handle; }

    bool GoHandle::operator==(const GoHandle &other) const
    { return handle == other.handle; }

    std::uintptr_t *GoHandle::resetAndGetAddressOf()
    {
        reset();
        return &handle;
    }

    void GoHandle::reset(std::uintptr_t newHandle)
    {
        reset();
        handle = newHandle;
    }

    std::uintptr_t GoHandle::release() noexcept
    {
        std::uintptr_t tmp = handle;
        handle = INVALID_HANDLE;
        return tmp;
    }

    const std::uintptr_t *const GoHandle::getAddressOf() const { return &handle; }

    std::uintptr_t GoHandle::get() const noexcept { return handle; }

    bool GoHandle::isValid() const { return handle != INVALID_HANDLE; }

    GoHandle::operator bool() const { return handle != INVALID_HANDLE; }

    GoHandle GoHandle::duplicate()
    {
        return GoHandle::Duplicate(handle);
    }

    GoHandle::~GoHandle() { reset(); }

    GoHandle &GoHandle::operator=(GoHandle &&other)
    {
        swap(*this, other);
        return *this;
    }

    GoHandle::GoHandle() : handle() {}

    GoHandle::GoHandle(GoHandle &&other)
    {
        swap(*this, other);
    }

    GoHandle::GoHandle(std::uintptr_t h)
        : handle(h)
    {
    }

    void swap(GoHandle &a, GoHandle &b)
    {
        std::swap(a.handle, b.handle);
    }

    GoHandle::GoHandle(const GoHandle &other)
        : handle(PanDuplicateHandle(other.handle))
    {
    }

    GoHandle &GoHandle::operator=(const GoHandle &other)
    {
        if (other != *this)
            handle = PanDuplicateHandle(other.handle);
        return *this;
    }

    GoHandle GoHandle::Duplicate(std::uintptr_t handle)
    {
        return GoHandle(PanDuplicateHandle(handle));
    }

    void GoHandle::reset()
    {
        if (handle != PAN_INVALID_HANDLE)
        {
            PanDeleteHandle(handle);
            handle = PAN_INVALID_HANDLE;
        }
    }

} // namespace Pan
