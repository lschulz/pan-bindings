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

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <asio.hpp>

#include "go_handle.hpp"

#if __INTELLISENSE__
    #define UNIX_DGRAM_AVAILABLE
    #define UNIX_STREAM_AVAILABLE
#else
#ifdef _WIN32
    #define UNIX_STREAM_AVAILABLE
#else
    #define UNIX_DGRAM_AVAILABLE
    #define UNIX_STREAM_AVAILABLE
#endif
#endif

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

namespace Pan {

enum class Error
{
    Ok             = 0,
    Failed         = 1,
    Deadline       = 2,
    NoPath         = 3,
    AddrSyntax     = 4,
    AddrResolution = 5,
    InvalidArg     = 6,
};

class Exception : public virtual std::exception
{
public:
    DLLEXPORT
    Exception(Error error);

    const std::error_code& code() const noexcept
    { return ec; }

    const char* what() const noexcept override
    { return message->c_str(); }

private:
    std::error_code ec;
    std::shared_ptr<std::string> message;
};

DLLEXPORT
std::error_code make_error_code(Error e);

DLLEXPORT
std::string GetLastError();

} // namespace Pan

namespace std {
template<> struct is_error_code_enum<Pan::Error> : true_type {};
}

namespace Pan {

typedef std::uint64_t IA;
typedef std::uint64_t IfID;

namespace udp {
    class Endpoint;
}

class PathInterface final
{
public:
    PathInterface() = default;
    explicit PathInterface(GoHandle&& handle) noexcept
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
    explicit PathFingerprint(GoHandle&& handle) noexcept
        : h(std::move(handle))
    {}

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    bool operator==(const PathFingerprint &other) const noexcept;
    DLLEXPORT
    bool operator!=(const PathFingerprint &other) const noexcept;

private:
    GoHandle h;
};

enum class LinkType
{
    Unspecified = 0, ///< Link type not specified
    Direct,          ///< Direct physical connection
    MultiHop,        ///< Connected with local routing/switching
    OpenNet,         ///< Connection overlayed over the public Internet
    Internal = 255,  ///< AS internal link (SCION does not provide link type for internal links)
};

struct GeoCoordinates
{
    float       latitude;
    float       longitude;
    std::string address;
};

struct PathHop
{
    IA             ia;
    IfID           ingress, egress;
    GeoCoordinates ingRouter, egrRouter;
    std::uint32_t  internalHops;
    std::string    notes;
};

struct PathLink
{
    LinkType                 type;
    std::chrono::nanoseconds latency;
    std::uint64_t            bandwidth;
};

class PathMeta
{
public:
    std::vector<PathHop>  hops;
    std::vector<PathLink> links;
};

class Path final
{
public:
    Path() = default;
    explicit Path(GoHandle&& handle) noexcept
        : h(std::move(handle))
    {}

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    std::string toString() const;

    DLLEXPORT
    IA getSource() const;
    DLLEXPORT
    IA getDestination() const;

    DLLEXPORT
    std::size_t dpLength() const;
    DLLEXPORT
    std::size_t dpLength(std::error_code& ec) const noexcept;

    DLLEXPORT
    PathFingerprint getFingerprint() const;
    DLLEXPORT
    bool containsInterface(const PathInterface &iface) const;

    DLLEXPORT
    std::optional<PathMeta> getMetadata() const;

private:
    GoHandle h;
};

inline std::ostream& operator<<(std::ostream& stream, const Path& path)
{
    stream << path.toString();
    return stream;
}

/// \brief Query paths to a particular destination AS.
/// \param[in] dst Destination ISD-ASN
DLLEXPORT
std::vector<Path> QueryPaths(IA dst);

/// \copydoc queryPaths(IA)
DLLEXPORT
std::vector<Path> QueryPaths(IA dst, std::error_code& ec) noexcept;

class PathPolicy
{
public:
    DLLEXPORT
    PathPolicy();
    virtual ~PathPolicy() = default;

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
    DLLEXPORT
    PathSelector();
    virtual ~PathSelector() = default;

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

public:
    // Callback for Go
    static std::uintptr_t cbPath(std::uint64_t ctx, std::uintptr_t user);
    static void cbInitialize(
        std::uintptr_t local, std::uintptr_t remote,
        std::uintptr_t* paths, size_t count, std::uintptr_t user);
    static void cbRefresh(std::uintptr_t* paths, size_t count, std::uintptr_t user);
    static void cbPathDown(std::uintptr_t pf, std::uintptr_t pi, uintptr_t user);
    static void cbClose(std::uintptr_t user);

protected:
    virtual Path path(std::uint64_t ctx) = 0;
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
    DLLEXPORT
    ReplySelector();
    virtual ~ReplySelector() = default;

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

public:
    // Callbacks for Go
    static std::uintptr_t cbPath(std::uint64_t ctx, std::uintptr_t remote, std::uintptr_t user);
    static void cbInitialize(std::uintptr_t local, std::uintptr_t user);
    static void cbRecord(std::uintptr_t remote, std::uintptr_t path, std::uintptr_t user);
    static void cbPathDown(std::uintptr_t pf, std::uintptr_t pi, std::uintptr_t user);
    static void cbClose(std::uintptr_t user);

protected:
    virtual Path path(std::uint64_t ctx, udp::Endpoint remote) = 0;
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
    explicit Endpoint(GoHandle&& handle) noexcept
        : h(std::move(handle))
    {}
    Endpoint(IA ia, const asio::ip::udp::endpoint& ep) noexcept
        : Endpoint(ia, ep.address(), ep.port())
    {}
    DLLEXPORT
    Endpoint(IA ia, const asio::ip::address& ip, std::uint16_t port) noexcept;

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    IA getIA() const;
    DLLEXPORT
    asio::ip::address getIP() const;
    DLLEXPORT
    std::uint16_t getPort() const;

    DLLEXPORT
    std::string toString() const;

    friend std::ostream& operator<<(std::ostream& stream, const Endpoint& ep)
    {
        stream << ep.toString();
        return stream;
    }

private:
    GoHandle h;
};

DLLEXPORT
Endpoint ResolveUDPAddr(const char* address);
DLLEXPORT
Endpoint ResolveUDPAddr(const char* address, std::error_code &ec) noexcept;

#ifdef UNIX_DGRAM_AVAILABLE
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

    ~ListenSockAdapter() { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    void close() noexcept;

private:
    DLLEXPORT
    ListenSockAdapter(GoHandle handle) noexcept;
    friend class ListenConn;

private:
    GoHandle h;
};
#endif // UNIX_DGRAM_AVAILABLE

#ifdef UNIX_STREAM_AVAILABLE
/// \brief Unix stream socket adapter (see PanNewListenSockAdapter())
///
/// Cannot be copied as we would have no way of knowing when the last copy goes
/// out of scope and close() should be called by the destructor without reference
/// counting. If required use a `std::shared_ptr`.
class ListenSSockAdapter final
{
public:
    ListenSSockAdapter() = default;
    ListenSSockAdapter(const ListenSSockAdapter& other) = delete;
    ListenSSockAdapter(ListenSSockAdapter&& other) = default;
    ListenSSockAdapter& operator=(const ListenSSockAdapter& other) = delete;
    ListenSSockAdapter& operator=(ListenSSockAdapter&& other) = default;

    ~ListenSSockAdapter() { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    void close() noexcept;

private:
    DLLEXPORT
    ListenSSockAdapter(GoHandle handle) noexcept;
    friend class ListenConn;

private:
    GoHandle h;
};
#endif // UNIX_STREAM_AVAILABLE

class ListenConn final
{
public:
    /// \brief Create the connection object without listening yet.
    DLLEXPORT
    ListenConn(std::unique_ptr<ReplySelector> selector = nullptr) noexcept;
    /// \brief Create the connection object and start listening.
    DLLEXPORT
    ListenConn(const char* bind, std::unique_ptr<ReplySelector> selector);
    /// \brief Create the connection object and start listening.
    DLLEXPORT
    ListenConn(const char* bind, std::unique_ptr<ReplySelector> selector, std::error_code &ec) noexcept;

    ListenConn(const ListenConn& other) = delete;
    ListenConn(ListenConn&& other) = default;

    ListenConn& operator=(const ListenConn& other) = delete;
    ListenConn& operator=(ListenConn&& other) = default;

    ~ListenConn() { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    void listen(const char* bind);
    DLLEXPORT
    void listen(const char* bind, std::error_code &ec) noexcept;

    DLLEXPORT
    void close() noexcept;

    DLLEXPORT
    Endpoint getLocalEndpoint() const;

    DLLEXPORT
    void setDeadline(std::chrono::milliseconds t);
    DLLEXPORT
    void setReadDeadline(std::chrono::milliseconds t);
    DLLEXPORT
    void setWriteDeadline(std::chrono::milliseconds t);

    DLLEXPORT
    std::size_t readFrom(asio::mutable_buffer buffer, Endpoint* from);
    DLLEXPORT
    std::size_t readFrom(asio::mutable_buffer buffer, Endpoint* from, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t readFromVia(asio::mutable_buffer buffer, Endpoint* from, Path* path);
    DLLEXPORT
    std::size_t readFromVia(asio::mutable_buffer buffer, Endpoint* from, Path* path, std::error_code& ec) noexcept;

    DLLEXPORT
    std::size_t writeTo(asio::const_buffer buffer, const Endpoint& to);
    DLLEXPORT
    std::size_t writeTo(asio::const_buffer buffer, const Endpoint& to, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t writeToWithCtx(std::uint64_t ctx, asio::const_buffer buffer, const Endpoint& to);
    DLLEXPORT
    std::size_t writeToWithCtx(std::uint64_t ctx, asio::const_buffer buffer, const Endpoint& to, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t writeToVia(asio::const_buffer buffer, const Endpoint& to, const Path& path);
    DLLEXPORT
    std::size_t writeToVia(asio::const_buffer buffer, const Endpoint& to, const Path& path, std::error_code& ec) noexcept;

#ifdef UNIX_DGRAM_AVAILABLE
    DLLEXPORT
    ListenSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath);
    DLLEXPORT
    ListenSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath, std::error_code &ec) noexcept;
#endif
#ifdef UNIX_STREAM_AVAILABLE
    DLLEXPORT
    ListenSSockAdapter createSSockAdapter(const char* goSocketPath);
    DLLEXPORT
    ListenSSockAdapter createSSockAdapter(const char* goSocketPath, std::error_code &ec) noexcept;
#endif

private:
    GoHandle h;
    std::unique_ptr<ReplySelector> selector;
};

#ifdef UNIX_DGRAM_AVAILABLE
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

    ~ConnSockAdapter() { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    void close() noexcept;

private:
    DLLEXPORT
    ConnSockAdapter(GoHandle handle) noexcept;
    friend class Conn;

private:
    GoHandle h;
};
#endif // UNIX_DGRAM_AVAILABLE

#ifdef UNIX_STREAM_AVAILABLE
/// \brief Unix datagram socket adapter (see PanNewConnSSockAdapter())
///
/// Cannot be copied as we would have no way of knowing when the last copy goes
/// out of scope and close() should be called by the destructor without reference
/// counting. If required use a `std::shared_ptr`.
class ConnSSockAdapter
{
public:
    ConnSSockAdapter() = default;
    ConnSSockAdapter(const ConnSSockAdapter& other) = delete;
    ConnSSockAdapter(ConnSSockAdapter&& other) = default;
    ConnSSockAdapter& operator=(const ConnSSockAdapter& other) = delete;
    ConnSSockAdapter& operator=(ConnSSockAdapter&& other) = default;

    ~ConnSSockAdapter() { close(); }

    operator bool() const noexcept { return h.isValid(); }
    bool isValid() const noexcept { return h.isValid(); }
    std::uintptr_t getHandle() const noexcept { return h.get(); }
    std::uintptr_t releaseHandle() noexcept { return h.release(); }

    DLLEXPORT
    void close() noexcept;

private:
    DLLEXPORT
    ConnSSockAdapter(GoHandle handle) noexcept;
    friend class Conn;

private:
    GoHandle h;
};
#endif // UNIX_STREAM_AVAILABLE

class Conn final
{
public:
    /// \brief Create to connection object without dialing.
    DLLEXPORT
    Conn(std::unique_ptr<PathPolicy> policy = nullptr,
        std::unique_ptr<PathSelector> selector = nullptr) noexcept;
    /// \brief Create and dial the connection.
    DLLEXPORT
    Conn(const char *local, const Endpoint& remote,
        std::unique_ptr<PathPolicy> policy, std::unique_ptr<PathSelector> selector);
    /// \brief Create and dial the connection.
    DLLEXPORT
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

    DLLEXPORT
    void dial(const char *local, const Endpoint& remote);
    DLLEXPORT
    void dial(const char *local, const Endpoint& remote, std::error_code &ec) noexcept;

    DLLEXPORT
    void close() noexcept;

    DLLEXPORT
    Endpoint getLocalEndpoint() const;
    DLLEXPORT
    Endpoint getRemoteEndpoint() const;

    DLLEXPORT
    void setDeadline(std::chrono::milliseconds t);
    DLLEXPORT
    void setReadDeadline(std::chrono::milliseconds t);
    DLLEXPORT
    void setWriteDeadline(std::chrono::milliseconds t);

    DLLEXPORT
    std::size_t read(asio::mutable_buffer buffer);
    DLLEXPORT
    std::size_t read(asio::mutable_buffer buffer, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t readVia(asio::mutable_buffer buffer, Path* path);
    DLLEXPORT
    std::size_t readVia(asio::mutable_buffer buffer, Path* path, std::error_code& ec) noexcept;

    DLLEXPORT
    std::size_t write(asio::const_buffer buffer);
    DLLEXPORT
    std::size_t write(asio::const_buffer buffer, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t writeWithCtx(std::uint64_t ctx, asio::const_buffer buffer);
    DLLEXPORT
    std::size_t writeWithCtx(std::uint64_t ctx, asio::const_buffer buffer, std::error_code& ec) noexcept;
    DLLEXPORT
    std::size_t writeVia(asio::const_buffer buffer, const Path& path);
    DLLEXPORT
    std::size_t writeVia(asio::const_buffer buffer, const Path& path, std::error_code& ec) noexcept;

#ifdef UNIX_DGRAM_AVAILABLE
    DLLEXPORT
    ConnSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath);
    DLLEXPORT
    ConnSockAdapter createSockAdapter(const char* goSocketPath, const char* cSocketPath, std::error_code &ec) noexcept;
#endif
#ifdef UNIX_STREAM_AVAILABLE
    DLLEXPORT
    ConnSSockAdapter createSSockAdapter(const char* goSocketPath);
    DLLEXPORT
    ConnSSockAdapter createSSockAdapter(const char* goSocketPath, std::error_code &ec) noexcept;
#endif

private:
    GoHandle h;
    std::unique_ptr<PathPolicy> policy;
    std::unique_ptr<PathSelector> selector;
};

} // namespace udp
} // namespace Pan
