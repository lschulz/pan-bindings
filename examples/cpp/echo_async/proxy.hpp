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

#include <asio.hpp>
#include <cstdint>


constexpr size_t STREAM_HEADER_LEN = 4;
constexpr size_t PROXY_HEADER_LEN = 32;
constexpr size_t CTX_HEADER_LEN = 8;
constexpr size_t MAX_MSG_LEN = 4096;

struct ScionUDPAddr
{
    uint8_t isd[2];
    uint8_t asn[6];
    asio::ip::address ip;
    uint16_t port;
};

void insertCtxHeader(std::vector<char>& buffer, uint64_t ctx);

ScionUDPAddr parseProxyHeader(const char* buffer, size_t len);

std::ostream& operator<<(std::ostream& stream, const ScionUDPAddr& addr);
