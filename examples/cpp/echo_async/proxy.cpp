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

#include "proxy.hpp"

#include <iostream>
#include <iomanip>


ScionUDPAddr parseProxyHeader(const char* buffer, size_t len)
{
    ScionUDPAddr addr;

    if (len < PROXY_HEADER_LEN) {
        throw std::runtime_error("Invalid unix socket packet header");
    }

    for (size_t i = 0; i < 2; ++i)
        addr.isd[i] = buffer[i];
    for (size_t i = 0; i < 6; ++i)
        addr.asn[i] = buffer[2 + i];

    uint32_t addrLen = *(uint32_t*)&buffer[8];
    if (addrLen == 4) {
        asio::ip::address_v4::bytes_type bytes;
        std::copy_n(buffer + 12, 4, bytes.begin());
        addr.ip = asio::ip::address_v4(bytes);
    } else if (addrLen == 16) {
        asio::ip::address_v6::bytes_type bytes;
        std::copy_n(buffer + 12, 16, bytes.begin());
        addr.ip = asio::ip::address_v6(bytes);
    } else {
        throw std::runtime_error("Invalid unix socket packet header");
    }

    addr.port = *(uint16_t*)&buffer[28];

    return addr;
}

std::ostream& operator<<(std::ostream& stream, const ScionUDPAddr& addr)
{
    stream << std::dec << ((uint32_t)addr.isd[1] | ((uint32_t)addr.isd[0]) << 8) << '-';
    stream << std::hex << std::setfill('0');
    stream.width(2);
    stream << +addr.asn[0] << +addr.asn[1] << ':';
    stream << +addr.asn[2] << +addr.asn[3] << ':';
    stream << +addr.asn[4] << +addr.asn[5] << ',';
    stream.width(0);
    if (addr.ip.is_v6()) stream << '[';
    stream << addr.ip;
    if (addr.ip.is_v6()) stream << ']';
    stream << ':' << std::dec << addr.port;
    return stream;
}
