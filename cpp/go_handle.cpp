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

#include "pan/go_handle.hpp"
#include "pan/pan.h"

namespace Pan {

DLLEXPORT
GoHandle::GoHandle(const GoHandle &other) noexcept
    : handle(PanDuplicateHandle(other.handle))
{}

DLLEXPORT
GoHandle& GoHandle::operator=(const GoHandle &other) noexcept
{
    if (other != *this)
        handle = PanDuplicateHandle(other.handle);
    return *this;
}

DLLEXPORT
GoHandle GoHandle::Duplicate(std::uintptr_t handle) noexcept
{
    return GoHandle(PanDuplicateHandle(handle));
}

DLLEXPORT
void GoHandle::reset() noexcept
{
    if (handle != PAN_INVALID_HANDLE) {
        PanDeleteHandle(handle);
        handle = PAN_INVALID_HANDLE;
    }
}

} // namespace Pan
