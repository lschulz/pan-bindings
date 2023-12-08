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

#include <boost/asio.hpp>

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
        using asio::local::datagram_protocol;

        count = args.count;

        auto tmp = fs::temp_directory_path();
        fs::path goSocketPath = tmp / "scion_async_client_go.sock";
        fs::path socketPath = tmp / "scion_async_client.sock";

        auto remote = Pan::udp::resolveUDPAddr(args.remoteAddr.c_str());
        conn.dial(args.localAddr.empty() ? NULL : args.localAddr.c_str(), remote);

        socket.open();
        fs::remove(socketPath);
        socket.bind(datagram_protocol::endpoint(socketPath));
        adapter = conn.createSockAdapter(goSocketPath.c_str(), socketPath.c_str());

        if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
        buffer.reserve(args.message.size());
        std::copy(args.message.cbegin(), args.message.cend(), std::back_inserter(buffer));

        socket.async_connect(
            datagram_protocol::endpoint(goSocketPath),
            std::bind(&Client::connected, this, _1));

        ioContext.run();

        socket.close();
        adapter.close();
        fs::remove(socketPath);
        return EXIT_SUCCESS;
    }

private:
    void connected(const system::error_code& error)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        socket.async_send(asio::buffer(buffer), std::bind(&Client::sent, this, _1, _2));
    }

    void sent(const system::error_code& error, size_t bytes)
    {

        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }
        ++msg_send;

        buffer.clear();
        buffer.resize(4096);
        socket.async_receive(asio::buffer(buffer), std::bind(&Client::received, this, _1, _2));
    }

    void received(const system::error_code& error, size_t bytes)
    {
        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        std::cout << "Received " << bytes << " bytes:\n";
        buffer.resize(bytes);
        printBuffer(std::cout, buffer) << '\n';

        if (msg_send < count)
        {
            connected( boost::system::error_code( ) );
        }
    }

private:
    Pan::udp::Conn conn;
    Pan::udp::ConnSockAdapter adapter;

    asio::io_context ioContext;
    asio::local::datagram_protocol::socket socket;
    int count;  // number of times to repeat the message
    int msg_send = 0; // number of messages send so far

    std::vector<char> buffer;
};
