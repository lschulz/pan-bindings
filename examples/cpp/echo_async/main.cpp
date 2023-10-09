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

#include "pan.hpp"
#include "common/message_parser.hpp"

#include <asio.hpp>
#include <getopt.h>

#include <array>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstddef>
#include <cctype>


static const size_t PROXY_HEADER_LEN = 32;


struct Arguments
{
    std::string localAddr;
    std::string remoteAddr;
    std::vector<char> message;
};

static bool parseArgs(int argc, char* argv[], Arguments& args)
{
    static const option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", required_argument, NULL, 'l' },
        { "remote", required_argument, NULL, 'r' },
        { "msg", required_argument, NULL, 'm' },
        {}
    };

    int opt = -1;
    while ((opt = getopt_long_only(argc, argv, "", longopts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'l':
            args.localAddr = optarg;
            break;
        case 'r':
            args.remoteAddr = optarg;
            break;
        case 'm':
        {
            int errorPos = 0;
            std::tie(args.message, errorPos) = parseString(optarg);
            if (errorPos >= 0) {
                std::cout << "Error parsing message at char " << errorPos << '\n';
                return false;
            }
            break;
        }
        case 'h':
        default:
            std::cout
                << "Usage: echo-async -local LOCAL -remote REMOTE -msg MESSAGE\n"
                << "  LOCAL   Local IP address and port (required for servers)\n"
                << "  REMOTE  Scion address of the remote server (only for clients)\n"
                << "  MESSAGE The message clients will send to the server\n";
            return false;
        }
    }

    // Check for mandatory options
    if (args.localAddr.empty() && args.remoteAddr.empty()) {
        std::cout << "At least one of local (for servers) and remote (for clients) is required\n";
        return false;
    }

    return true;
}

struct ScionUDPAddr
{
    uint8_t isd[2];
    uint8_t asn[6];
    asio::ip::address ip;
    uint16_t port;
};

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

class Server
{
public:
    Server()
        : socket(ioContext), signals(ioContext, SIGINT), buffer(2048)
    {}

    int listen(Arguments& args)
    {
        using namespace std::placeholders;
        using asio::local::datagram_protocol;

        static const char* goSocketPath = "/tmp/scion_async_server_go.sock";
        static const char* socketPath = "/tmp/scion_async_server.sock";

        conn.listen(args.localAddr.c_str());

        socket.open();
        std::remove(socketPath);
        socket.bind(datagram_protocol::endpoint(socketPath));
        adapter = conn.createSockAdapter(goSocketPath, socketPath);

        socket.async_connect(
            datagram_protocol::endpoint(goSocketPath),
            std::bind(&Server::connected, this, _1));
        signals.async_wait(std::bind(&Server::cancel, this, _1, _2));

        ioContext.run();

        socket.close();
        adapter.close();
        std::remove(socketPath);
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
            ScionUDPAddr from = parseProxyHeader(buffer.data(), buffer.size());

            size_t dataLen = bytes - PROXY_HEADER_LEN;
            std::cout << "Received " << dataLen << " bytes from " << from << ":\n";
            printBuffer(std::cout, buffer.data() + PROXY_HEADER_LEN, dataLen) << "\n";
            socket.async_send(asio::buffer(buffer, bytes), std::bind(&Server::sent, this, _1, _2));
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

class Client
{
public:
    Client()
        : socket(ioContext)
    {}

    int connect(Arguments& args)
    {
        using namespace std::placeholders;
        using asio::local::datagram_protocol;

        static const char* goSocketPath = "/tmp/scion_async_client_go.sock";
        static const char* socketPath = "/tmp/scion_async_client.sock";

        auto remote = Pan::udp::resolveUDPAddr(args.remoteAddr.c_str());
        conn.dial(args.localAddr.empty() ? NULL : args.localAddr.c_str(), remote);

        socket.open();
        std::remove(socketPath);
        socket.bind(datagram_protocol::endpoint(socketPath));
        adapter = conn.createSockAdapter(goSocketPath, socketPath);

        if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
        buffer.reserve(args.message.size());
        std::copy(args.message.cbegin(), args.message.cend(), std::back_inserter(buffer));

        socket.async_connect(
            datagram_protocol::endpoint(goSocketPath),
            std::bind(&Client::connected, this, _1));

        ioContext.run();

        socket.close();
        adapter.close();
        std::remove(socketPath);
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

        socket.async_send(asio::buffer(buffer), std::bind(&Client::sent, this, _1, _2));
    }

    void sent(const asio::error_code& error, size_t bytes)
    {
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

        buffer.clear();
        buffer.resize(4096);
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
    Pan::udp::ConnSockAdapter adapter;

    asio::io_context ioContext;
    asio::local::datagram_protocol::socket socket;

    std::vector<char> buffer;
};

int main(int argc, char* argv[])
{
    Arguments args;
    if (!parseArgs(argc, argv, args)) {
        return EXIT_FAILURE;
    }

    try {
        if (args.remoteAddr.empty()) {
            return Server().listen(args);
        }
        else {
            return Client().connect(args);
        }
    }
    catch (Pan::Exception &e) {
        std::cout << "PAN error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
