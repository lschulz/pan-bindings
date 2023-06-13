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

#include "reply_selector.hpp"

using namespace Pan;


//////////////////////////
// DefaultReplySelector //
//////////////////////////

Path DefaultReplySelector::path(udp::Endpoint remote)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto iter = remotes.find(remote.toString());
    if (iter != remotes.end())
        return iter->second;
    else
        return Path();
}

void DefaultReplySelector::initialize(udp::Endpoint local)
{
}

void DefaultReplySelector::record(udp::Endpoint remote, Path path)
{
    if (!path) return;
    std::lock_guard<std::mutex> lock(mutex);

    remotes.emplace(remote.toString(), std::move(path));
}

void DefaultReplySelector::pathDown(PathFingerprint pf, PathInterface pi)
{
}

void DefaultReplySelector::close()
{
}
