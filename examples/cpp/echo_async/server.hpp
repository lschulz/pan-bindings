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

#include "args.hpp"
#include "proxy.hpp"
#include "common/message_parser.hpp"
#include "pan/pan.hpp"

#include <asio.hpp>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <vector>


class Server
{
public:
    Server()
        : socket(ioContext), signals(ioContext, SIGINT), buffer(2048)
    {}

    int listen(Arguments& args)
    {
        namespace fs = std::filesystem;
        using namespace std::placeholders;
        using asio::local::datagram_protocol;

        auto tmp = fs::temp_directory_path();
        fs::path goSocketPath = tmp / "scion_async_server_go.sock";
        fs::path socketPath = tmp / "scion_async_server.sock";

        conn.listen(args.localAddr.c_str());

        socket.open();
        fs::remove(socketPath);
        socket.bind(datagram_protocol::endpoint(socketPath));
        adapter = conn.createSockAdapter(goSocketPath.c_str(), socketPath.c_str());

        socket.async_connect(
            datagram_protocol::endpoint(goSocketPath),
            std::bind(&Server::connected, this, _1));
        signals.async_wait(std::bind(&Server::cancel, this, _1, _2));

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

        auto local = conn.getLocalEndpoint();
        std::cout << "Server listening at " << local.toString() << '\n';

        socket.async_receive(asio::buffer(buffer), std::bind(&Server::received, this, _1, _2));
    }

    void received(const asio::error_code& error, size_t bytes)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        try {
            ScionUDPAddr from = parseProxyHeader(buffer.data(), bytes);

            size_t dataLen = bytes - PROXY_HEADER_LEN;
            std::cout << "Received " << dataLen << " bytes from " << from << ":\n";
            printBuffer(std::cout, buffer.data() + PROXY_HEADER_LEN, dataLen) << "\n";
            buffer.insert(buffer.begin() + PROXY_HEADER_LEN, CTX_HEADER_LEN, 0);
            socket.async_send(
                asio::buffer(buffer, bytes + CTX_HEADER_LEN),
                std::bind(&Server::sent, this, _1, _2));
        }
        catch (const std::exception& e) {
            std::cerr << "Received invalid packet on unix socket: " << e.what() << std::endl;

            buffer.clear();
            buffer.resize(4096);
            socket.async_receive(asio::buffer(buffer), std::bind(&Server::received, this, _1, _2));
        }
    }

    void sent(const asio::error_code& error, size_t bytes)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        buffer.clear(),
        buffer.resize(4096);
        socket.async_receive(asio::buffer(buffer), std::bind(&Server::received, this, _1, _2));
    }

    void cancel(const asio::error_code& error, int signal)
    {
        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        if (signal == SIGINT) {
            socket.close();
        }
    }

private:
    Pan::udp::ListenConn conn;
    Pan::udp::ListenSockAdapter adapter;

    asio::io_context ioContext;
    asio::local::datagram_protocol::socket socket;
    asio::signal_set signals;

    std::vector<char> buffer;
};
