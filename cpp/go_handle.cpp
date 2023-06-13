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

#include "go_handle.hpp"
#include "pan.h"


namespace Pan {

GoHandle::GoHandle(const GoHandle &other)
    : handle(PanDuplicateHandle(other.handle))
{}

GoHandle& GoHandle::operator=(const GoHandle &other)
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
    if (handle != PAN_INVALID_HANDLE) {
        PanDeleteHandle(handle);
        handle = PAN_INVALID_HANDLE;
    }
}

} // namespace Pan
