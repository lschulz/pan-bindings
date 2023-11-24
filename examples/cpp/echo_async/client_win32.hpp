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

#include "args.hpp"
#include "proxy.hpp"
#include "common/message_parser.hpp"
#include "pan/pan.hpp"

#include <asio.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <vector>


class Client
{
public:
    Client()
        : socket(ioContext)
    {}

    int connect(Arguments& args)
    {
        namespace fs = std::filesystem;
        using namespace std::placeholders;
        using asio::local::stream_protocol;

        auto tmp = fs::temp_directory_path();
        fs::path goSocketPath = tmp / "scion_async_client_go.sock";
        fs::path socketPath = tmp / "scion_async_client.sock";

        auto remote = Pan::udp::resolveUDPAddr(args.remoteAddr.c_str());
        conn.dial(args.localAddr.empty() ? NULL : args.localAddr.c_str(), remote);

        socket.open();
        fs::remove(socketPath);
        socket.bind(stream_protocol::endpoint(socketPath.string()));
        adapter = conn.createSSockAdapter(goSocketPath.string().c_str());

        if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
        buffer.reserve(args.message.size());
        std::copy(args.message.cbegin(), args.message.cend(), std::back_inserter(buffer));
        headerBuffer.resize(STREAM_HEADER_LEN);
        auto uintBytes = static_cast<uint32_t>(buffer.size());
        std::memcpy(headerBuffer.data(), &uintBytes, sizeof(uint32_t));

        socket.async_connect(
            stream_protocol::endpoint(goSocketPath.string()),
            std::bind(&Client::connected, this, _1));

        ioContext.run();

        socket.close();
        adapter.close();
        fs::remove(socketPath);
        return EXIT_SUCCESS;
    }

private:
    void connected(const asio::error_code& error)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        std::array<asio::const_buffer, 2> buffers = {
            asio::buffer(headerBuffer),
            asio::buffer(buffer)
        };
        socket.async_send(buffers, std::bind(&Client::sent, this, _1, _2));
    }

    void sent(const asio::error_code& error, size_t bytes)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        headerBuffer.clear();
        headerBuffer.resize(STREAM_HEADER_LEN);
        socket.async_receive(
            asio::buffer(headerBuffer), std::bind(&Client::receivedHeader, this, _1, _2));
    }

    void receivedHeader(const asio::error_code& error, size_t bytes)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        if (bytes < STREAM_HEADER_LEN) {
            std::cerr << "Short stream header" << std::endl;
            return;
        }

        uint32_t msglen = 0;
        std::memcpy(&msglen, headerBuffer.data(), sizeof(uint32_t));
        if (msglen > MAX_MSG_LEN) {
            std::cerr << "Invalid message on unix stream socket" << std::endl;
            return;
        }

        buffer.clear();
        buffer.resize(msglen);
        socket.async_receive(asio::buffer(buffer), std::bind(&Client::received, this, _1, _2));
    }

    void received(const asio::error_code& error, size_t bytes)
    {
        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        std::cout << "Received " << bytes << " bytes:\n";
        buffer.resize(bytes);
        printBuffer(std::cout, buffer) << '\n';
    }

private:
    Pan::udp::Conn conn;
    Pan::udp::ConnSSockAdapter adapter;

    asio::io_context ioContext;
    asio::local::stream_protocol::socket socket;

    std::vector<char> headerBuffer, buffer;
};
