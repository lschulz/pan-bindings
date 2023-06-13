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

#include "selector.hpp"

using namespace Pan;


/////////////////////
// DefaultSelector //
/////////////////////

Path DefaultSelector::path()
{
    std::lock_guard<std::mutex> lock(mutex);

    if (!paths.empty())
        return paths[currentPath];
    else
        return Path();
}

void DefaultSelector::initialize(
    udp::Endpoint local, udp::Endpoint remote, std::vector<Path>& paths)
{
    std::lock_guard<std::mutex> lock(mutex);
    this->paths = std::move(paths);
    currentPath = 0;
}

void DefaultSelector::refresh(std::vector<Pan::Path>& newPaths)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto currentFp = paths[currentPath].getFingerprint();
    size_t count = newPaths.size();
    for (size_t i = 0; i < count; ++i) {
        if (newPaths[i].getFingerprint() == currentFp) {
            currentPath = i;
            break;
        }
    }

    paths = newPaths;
}

void DefaultSelector::pathDown(PathFingerprint pf, PathInterface pi)
{
    std::lock_guard<std::mutex> lock(mutex);

    if (!paths.empty()) {
        auto& current = paths[currentPath];
        if (current.getFingerprint() == pf || current.containsInterface(pi)) {
            currentPath = (currentPath + 1) % paths.size();
        }
    }
}

void DefaultSelector::close()
{
}
