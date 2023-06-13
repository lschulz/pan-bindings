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
#include <vector>


/// \brief Path selector that selects the first available path.
class DefaultSelector : public Pan::PathSelector
{
public:
    DefaultSelector() = default;

protected:
    Pan::Path path() override;
    void initialize(
        Pan::udp::Endpoint local, Pan::udp::Endpoint remote,
        std::vector<Pan::Path>& paths) override;
    void refresh(std::vector<Pan::Path>& paths) override;
    void pathDown(Pan::PathFingerprint pf, Pan::PathInterface pi) override;
    void close() override;

private:
    mutable std::mutex mutex;
    std::vector<Pan::Path> paths;
    unsigned int currentPath = 0;
};
