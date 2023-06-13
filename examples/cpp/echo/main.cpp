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
#include "policy.hpp"
#include "reply_selector.hpp"
#include "selector.hpp"
#include "ncurses_helper.hpp"

#include <getopt.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstddef>
#include <cctype>


struct Arguments
{
    std::string localAddr;
    std::string remoteAddr;
    std::vector<char> message;
    int count = 1;
    bool interactive = false;
    bool show_path = false;
    bool quiet = false;
};

static bool parseArgs(int argc, char* argv[], Arguments& args)
{
    static const option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", required_argument, NULL, 'l' },
        { "remote", required_argument, NULL, 'r' },
        { "msg", required_argument, NULL, 'm' },
        { "count", required_argument, NULL, 'c' },
        { "interactive", no_argument, NULL, 'i'},
        { "show-path", no_argument, NULL, 's'},
        { "quiet", no_argument, NULL, 'q'},
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
        case 'c':
        {
            std::stringstream stream(optarg);
            stream >> args.count;
            if (!stream || args.count < 0) {
                std::cout << "Invalid value for COUNT\n";
                return false;
            }
            break;
        }
        case 'i':
            args.interactive = true;
            break;
        case 's':
            args.show_path = true;
            break;
        case 'q':
            args.quiet = true;
            break;
        case 'h':
        default:
            std::cout
                << "Usage: echo -local LOCAL -remote REMOTE -msg MESSAGE -count COUNT\n"
                << "  LOCAL   Local IP address and port (required for servers)\n"
                << "  REMOTE  Scion address of the remote server (only for clients)\n"
                << "  MESSAGE The message clients will send to the server\n"
                << "  COUNT   Number of messages to send\n"
                << "Optional Flags:\n"
                << "  -interactive Prompt for path selection (client only)\n"
                << "  -show-path   Print the paths taken by each packet\n"
                << "  -quiet       Only print response from server (client only)\n";
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

void writeBuffer(Pan::udp::ListenConn& conn, const Pan::udp::Endpoint& to,
    const char* buffer, size_t len, size_t& written)
{
    written = 0;
    while (len > written) {
        int n = conn.writeTo(asio::buffer(buffer + written, len - written), to);
        written += n;
    }
}

int runServer(Arguments& args)
{
    using namespace std::chrono_literals;

    Pan::udp::ListenConn conn(
        args.localAddr.c_str(),
        std::make_unique<DefaultReplySelector>());

    ncurses::initServer();
    auto local = conn.getLocalEndpoint();
    std::stringstream stream;
    stream << "Server listening at " << local.toString() << '\n';
    stream << "Press q to quit.\n";
    ncurses::print(stream.str().c_str());

    std::vector<char> buffer(2028);
    Pan::udp::Endpoint from;
    Pan::Path path;

    while (ncurses::getChar() != 'q')
    {
        ncurses::refreshScreen();
        size_t read = 0;
        conn.setReadDeadline(100ms);
        std::error_code ec;
        if (args.show_path)
            read = conn.readFromVia(asio::buffer(buffer), &from, &path, ec);
        else
            read = conn.readFrom(asio::buffer(buffer), &from, ec);
        if (!ec) {
            stream.str("");
            stream.clear();
            stream << "Received " << read << " bytes from " << from << ":\n";
            printBuffer(stream, buffer.data(), read) << "\n";
            if (path) stream << "Path: " << path.toString() << '\n';
            ncurses::print(stream.str().c_str());

            size_t written = 0;
            writeBuffer(conn, from, buffer.data(), read, written);
        }
        else if (ec.value() != (int)Pan::Error::Deadline) {
            ncurses::endServer();
            return EXIT_FAILURE;
        }
    }
    ncurses::endServer();

    return EXIT_SUCCESS;
}

int runClient(Arguments& args)
{
    using namespace std::chrono_literals;

    std::error_code ec;
    auto remote = Pan::udp::resolveUDPAddr(args.remoteAddr.c_str(), ec);
    if (ec) {
        std::cout << "Address resolution error: " << ec.message() << '\n';
        return EXIT_FAILURE;
    }

    Pan::udp::Conn conn(
        args.localAddr.empty() ? NULL : args.localAddr.c_str(),
        remote,
        args.interactive ? std::make_unique<InteractivePolicy>() : nullptr,
        std::make_unique<DefaultSelector>()
    );

    Pan::Path path;
    std::vector<char> buffer(2048);
    if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
    for (int i = 0; i < args.count; ++i) {
        size_t written = conn.write(asio::buffer(args.message));

        conn.setDeadline(1s);
        size_t read = 0;
        if (args.show_path)
            read = conn.readVia(asio::buffer(buffer), &path);
        else
            read = conn.read(asio::buffer(buffer));
        if (!args.quiet){
            std::cout << "Received " << read << " bytes:\n";
            printBuffer(std::cout, buffer.data(), read) << '\n';
            if (path) std::cout << "Path: " << path.toString() << '\n';
        } else {
            printEscapedString(std::cout, buffer.data(), read) << '\n';
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    Arguments args;
    if (!parseArgs(argc, argv, args)) {
        return EXIT_FAILURE;
    }

    try {
        if (args.remoteAddr.empty()) {
            return runServer(args);
        }
        else {
            return runClient(args);
        }
    }
    catch (Pan::Exception &e) {
        std::cout << "PAN error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
