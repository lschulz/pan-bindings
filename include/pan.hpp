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

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <asio.hpp>

#include "go_handle.hpp"


namespace Pan {

enum class Error
{
    Ok             = 0,
    Failed         = 1,
    Deadline       = 2,
    NoPath         = 3,
    AddrSyntax     = 4,
    AddrResolution = 5
};

class Exception : public virtual std::exception
{
public:
    Exception(std::uint32_t error);

    const std::error_code& code() const noexcept
    { return ec; }

    const char* what() const noexcept override
    { return message->c_str(); }

private:
    std::error_code ec;
    std::shared_ptr<std::string> message;
};

typedef std::uint64_t IA;

namespace udp {
    class Endpoint;
}

class PathInterface final
{
public:
    PathInterface() = default;
    explicit PathInterface(GoHandle&& handle)
        : h(std::move(handle))
    {}

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

private:
    GoHandle h;
};

class PathFingerprint final
{
public:
    PathFingerprint() = default;
    explicit PathFingerprint(GoHandle&& handle)
        : h(std::move(handle))
    {}

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    bool operator==(const PathFingerprint &other) const noexcept;
    bool operator!=(const PathFingerprint &other) const noexcept;

private:
    GoHandle h;
};

class Path final
{
public:
    Path() = default;
    explicit Path(GoHandle&& handle)
        : h(std::move(handle))
    {}

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    std::string toString() const;

    PathFingerprint getFingerprint() const;
    bool containsInterface(const PathInterface &iface) const;

private:
    GoHandle h;
};

class PathPolicy
{
public:
    PathPolicy();

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

public:
    // Callbacks for Go
    static std::size_t cbFilter(std::uintptr_t* paths, std::size_t count, std::uintptr_t user);

protected:
    using PathTag = std::uintptr_t;
    using Paths = std::vector<std::pair<Path, PathTag>>;
    virtual void filter(Paths& paths) = 0;

private:
    GoHandle h;
};

class PathSelector
{
public:
    PathSelector();

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

public:
    // Callback for Go
    static std::uintptr_t cbPath(std::uintptr_t user);
    static void cbInitialize(
        std::uintptr_t local, std::uintptr_t remote,
        std::uintptr_t* paths, size_t count, std::uintptr_t user);
    static void cbRefresh(std::uintptr_t* paths, size_t count, std::uintptr_t user);
    static void cbPathDown(std::uintptr_t pf, std::uintptr_t pi, uintptr_t user);
    static void cbClose(std::uintptr_t user);

protected:
    virtual Path path() = 0;
    virtual void initialize(
        udp::Endpoint local, udp::Endpoint remote, std::vector<Path>& paths) = 0;
    virtual void refresh(std::vector<Path>& paths) = 0;
    virtual void pathDown(PathFingerprint pf, PathInterface pi) = 0;
    virtual void close() = 0;

private:
    GoHandle h;
};

class ReplySelector
{
public:
    ReplySelector();

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

public:
    // Callbacks for Go
    static std::uintptr_t cbPath(std::uintptr_t remote, std::uintptr_t user);
    static void cbInitialize(std::uintptr_t local, std::uintptr_t user);
    static void cbRecord(std::uintptr_t remote, std::uintptr_t path, std::uintptr_t user);
    static void cbPathDown(std::uintptr_t pf, std::uintptr_t pi, std::uintptr_t user);
    static void cbClose(std::uintptr_t user);

protected:
    virtual Path path(udp::Endpoint remote) = 0;
    virtual void initialize(udp::Endpoint local) = 0;
    virtual void record(udp::Endpoint remote, Path path) = 0;
    virtual void pathDown(PathFingerprint pf, PathInterface pi) = 0;
    virtual void close() = 0;

private:
    GoHandle h;
};

namespace udp {

class Endpoint final
{
public:
    Endpoint() = default;
    explicit Endpoint(GoHandle&& handle)
        : h(std::move(handle))
    {}
    Endpoint(IA ia, const asio::ip::udp::endpoint& ep)
        : Endpoint(ia, ep.address(), ep.port())
    {}
    Endpoint(IA ia, const asio::ip::address& ip, std::uint16_t port);

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    IA getIA() const;
    asio::ip::address getIP() const;
    std::uint16_t getPort() const;

    std::string toString() const;

    friend std::ostream& operator<<(std::ostream& stream, const Endpoint& ep)
    {
        stream << ep.toString();
        return stream;
    }

private:
    GoHandle h;
};

Endpoint resolveUDPAddr(const char* address);
Endpoint resolveUDPAddr(const char* address, std::error_code &ec) noexcept;

/// \brief Unix datagram socket adapter (see PanNewListenSockAdapter())
///
/// Cannot be copied as we would have no way of knowing when the last copy goes
/// out of scope and close() should be called by the destructor without reference
/// counting. If required use a `std::shared_ptr`.
class ListenSockAdapter final
{
public:
    ListenSockAdapter() = default;
    ListenSockAdapter(const ListenSockAdapter& other) = delete;
    ListenSockAdapter(ListenSockAdapter&& other) = default;
    ListenSockAdapter& operator=(const ListenSockAdapter& other) = delete;
    ListenSockAdapter& operator=(ListenSockAdapter&& other) = default;

    ~ListenSockAdapter() noexcept { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    void close() noexcept;

private:
    ListenSockAdapter(GoHandle handle);
    friend class ListenConn;

private:
    GoHandle h;
};

class ListenConn final
{
public:
    /// \brief Create the connection object without listening yet.
    ListenConn(std::unique_ptr<ReplySelector> selector = nullptr) noexcept;
    /// \brief Create the connection object and start listening.
    ListenConn(const char* bind, std::unique_ptr<ReplySelector> selector);
    /// \brief Create the connection object and start listening.
    ListenConn(const char* bind, std::unique_ptr<ReplySelector> selector, std::error_code &ec) noexcept;

    ListenConn(const ListenConn& other) = delete;
    ListenConn(ListenConn&& other) = default;

    ListenConn& operator=(const ListenConn& other) = delete;
    ListenConn& operator=(ListenConn&& other) = default;

    ~ListenConn() noexcept { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    void listen(const char* bind);
    void listen(const char* bind, std::error_code &ec) noexcept;

    void close() noexcept;

    Endpoint getLocalEndpoint() const;

    void setDeadline(std::chrono::milliseconds t);
    void setReadDeadline(std::chrono::milliseconds t);
    void setWriteDeadline(std::chrono::milliseconds t);

    std::size_t readFrom(asio::mutable_buffer buffer, Endpoint* from);
    std::size_t readFrom(asio::mutable_buffer buffer, Endpoint* from, std::error_code& ec) noexcept;
    std::size_t readFromVia(asio::mutable_buffer buffer, Endpoint* from, Path* path);
    std::size_t readFromVia(asio::mutable_buffer buffer, Endpoint* from, Path* path, std::error_code& ec) noexcept;

    std::size_t writeTo(asio::const_buffer buffer, const Endpoint& to);
    std::size_t writeTo(asio::const_buffer buffer, const Endpoint& to, std::error_code& ec) noexcept;
    std::size_t writeToVia(asio::const_buffer buffer, const Endpoint& to, const Path& path);
    std::size_t writeToVia(asio::const_buffer buffer, const Endpoint& to, const Path& path, std::error_code& ec) noexcept;

    ListenSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath);
    ListenSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath, std::error_code &ec);

private:
    GoHandle h;
    std::unique_ptr<ReplySelector> selector;
};

/// \brief Unix datagram socket adapter (see PanNewConnSockAdapter())
///
/// Cannot be copied as we would have no way of knowing when the last copy goes
/// out of scope and close() should be called by the destructor without reference
/// counting. If required use a `std::shared_ptr`.
class ConnSockAdapter
{
public:
    ConnSockAdapter() = default;
    ConnSockAdapter(const ConnSockAdapter& other) = delete;
    ConnSockAdapter(ConnSockAdapter&& other) = default;
    ConnSockAdapter& operator=(const ConnSockAdapter& other) = delete;
    ConnSockAdapter& operator=(ConnSockAdapter&& other) = default;

    ~ConnSockAdapter() noexcept { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    void close() noexcept;

private:
    ConnSockAdapter(GoHandle handle);
    friend class Conn;

private:
    GoHandle h;
};

class Conn final
{
public:
    /// \brief Create to connection object without dialing.
    Conn(std::unique_ptr<PathPolicy> policy = nullptr,
        std::unique_ptr<PathSelector> selector = nullptr) noexcept;
    /// \brief Create and dial the connection.
    Conn(const char *local, const Endpoint& remote,
        std::unique_ptr<PathPolicy> policy, std::unique_ptr<PathSelector> selector);
    /// \brief Create and dial the connection.
    Conn(const char *local, const Endpoint& remote,
        std::unique_ptr<PathPolicy> policy, std::unique_ptr<PathSelector> selector,
        std::error_code &ec) noexcept;

    Conn(const Conn& other) = delete;
    Conn(Conn&& other) = default;

    Conn& operator=(const Conn& other) = delete;
    Conn& operator=(Conn&& other) = default;

    ~Conn() noexcept { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    void dial(const char *local, const Endpoint& remote);
    void dial(const char *local, const Endpoint& remote, std::error_code &ec) noexcept;

    void close() noexcept;

    Endpoint getLocalEndpoint() const;
    Endpoint getRemoteEndpoint() const;

    void setDeadline(std::chrono::milliseconds t);
    void setReadDeadline(std::chrono::milliseconds t);
    void setWriteDeadline(std::chrono::milliseconds t);

    std::size_t read(asio::mutable_buffer buffer);
    std::size_t read(asio::mutable_buffer buffer, std::error_code& ec) noexcept;
    std::size_t readVia(asio::mutable_buffer buffer, Path* path);
    std::size_t readVia(asio::mutable_buffer buffer, Path* path, std::error_code& ec) noexcept;

    std::size_t write(asio::const_buffer buffer);
    std::size_t write(asio::const_buffer buffer, std::error_code& ec) noexcept;
    std::size_t writeVia(asio::const_buffer buffer, const Path& path);
    std::size_t writeVia(asio::const_buffer buffer, const Path& path, std::error_code& ec) noexcept;

    ConnSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath);
    ConnSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath, std::error_code &ec) noexcept;

private:
    GoHandle h;
    std::unique_ptr<PathPolicy> policy;
    std::unique_ptr<PathSelector> selector;
};

} // namespace udp
} // namespace Pan

namespace std
{
    template <>
    struct is_error_code_enum<Pan::Error> : true_type {};
}
