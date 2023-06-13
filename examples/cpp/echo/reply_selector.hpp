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

#include "pan.hpp"

#include <mutex>
#include <string>
#include <unordered_map>


/// \brief Reply on the same path the remote end used.
class DefaultReplySelector : public Pan::ReplySelector
{
public:
    DefaultReplySelector() = default;

protected:
    Pan::Path path(Pan::udp::Endpoint remote) override;
    void initialize(Pan::udp::Endpoint local) override;
    void record(Pan::udp::Endpoint remote, Pan::Path path) override;
    void pathDown(Pan::PathFingerprint pf, Pan::PathInterface pi) override;
    void close() override;

private:
    mutable std::mutex mutex;
    std::unordered_map<std::string, Pan::Path> remotes;
};
