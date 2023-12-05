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

#include "pan/pan.hpp"
#include "pan/pan.h"

#include <cassert>
#include <cstdlib>

using std::uint8_t;
using std::uint32_t;
using std::size_t;
using std::uintptr_t;

namespace {

struct FreeDeleter { void operator()(void* p) const { ::free(p); } };
using CString = std::unique_ptr<char, FreeDeleter>;

struct PanErrorCategory : public std::error_category
{
    const char* name() const noexcept
    {
        return "PAN C++ Wrapper";
    }

    std::string message(int errorCode) const noexcept
    {
        using Pan::Error;
        switch (static_cast<Error>(errorCode))
        {
        case Error::Ok:
            return "No error";
        case Error::Failed:
            return "Operation failed";
        case Error::Deadline:
            return "Deadline exceeded";
        case Error::NoPath:
            return "No path to destination is known";
        case Error::AddrSyntax:
            return "Invalid address syntax";
        case Error::AddrResolution:
            return "Address resolution failed";
        default:
            return "Invalid error code";
        }
    }
};

} // anonymous namespace

/// \brief The one and only instance of PanErrorCategory
PanErrorCategory panErrorCategory;


namespace Pan {

static std::error_code make_error_code(PanError e)
{
    return { static_cast<int>(e), panErrorCategory };
}

Exception::Exception(std::uint32_t error)
    : ec(make_error_code(error))
    , message(std::make_shared<std::string>(ec.message()))
{}

/////////////////////
// PathFingerprint //
/////////////////////

DLLEXPORT
bool PathFingerprint::operator==(const PathFingerprint& other) const noexcept
{
    if (h.isValid() && other.h.isValid())
        return PanPathFingerprintAreEqual(h.get(), other.h.get());
    else
        return false;
}

DLLEXPORT
bool PathFingerprint::operator!=(const PathFingerprint& other) const noexcept
{
    if (h.isValid() && other.h.isValid())
        return !PanPathFingerprintAreEqual(h.get(), other.h.get());
    else
        return false;
}

//////////
// Path //
//////////

DLLEXPORT
PathFingerprint::PathFingerprint() {}

DLLEXPORT
std::string Path::toString() const
{
    return CString(PanPathToString(h.get())).get();
}

DLLEXPORT
PathFingerprint Path::getFingerprint() const
{
    return PathFingerprint(GoHandle(PanPathGetFingerprint(h.get())));
}

DLLEXPORT
bool Path::containsInterface(const PathInterface &iface) const
{
    return PanPathContainsInterface(h.get(), iface.getHandle());
}

////////////////
// PathPolicy //
////////////////

DLLEXPORT
PathPolicy::PathPolicy()
{
    h.reset(PanNewCPolicy(&PathPolicy::cbFilter, reinterpret_cast<uintptr_t>(this)));
}

size_t PathPolicy::cbFilter(uintptr_t* paths, size_t count, uintptr_t user)
{
    auto self = reinterpret_cast<PathPolicy*>(user);

    Paths pathObjs;
    pathObjs.reserve(count);
    for (size_t i = 0; i < count; ++i)
        pathObjs.emplace_back(Path(GoHandle::Duplicate(paths[i])), paths[i]);

    self->filter(pathObjs);

    size_t newCount = pathObjs.size();
    assert(newCount <= count);
    for (size_t i = 0; i < newCount; ++i) {
        paths[i] = pathObjs[i].second;
    }
    return newCount;
}

//////////////////
// PathSelector //
//////////////////

DLLEXPORT
PathSelector::PathSelector()
{
    struct PanSelectorCallbacks callbacks = {
        &PathSelector::cbPath,
        &PathSelector::cbInitialize,
        &PathSelector::cbRefresh,
        &PathSelector::cbPathDown,
        &PathSelector::cbClose
    };
    h.reset(PanNewCSelector(&callbacks, reinterpret_cast<uintptr_t>(this)));
}

PanPath PathSelector::cbPath(uintptr_t user)
{
    auto self = reinterpret_cast<PathSelector*>(user);
    return self->path().releaseHandle();
}

void PathSelector::cbInitialize(
    uintptr_t local, uintptr_t remote, uintptr_t *paths, size_t count, uintptr_t user)
{
    auto self = reinterpret_cast<PathSelector*>(user);

    std::vector<Path> pathObjs;
    pathObjs.reserve(count);
    for (size_t i = 0; i < count; ++i)
        pathObjs.emplace_back(GoHandle(paths[i]));

    self->initialize(
        udp::Endpoint(GoHandle(local)),
        udp::Endpoint(GoHandle(remote)),
        pathObjs);
}

void PathSelector::cbRefresh(uintptr_t *paths, size_t count, uintptr_t user)
{
    auto self = reinterpret_cast<PathSelector*>(user);

    std::vector<Path> pathObjs;
    pathObjs.reserve(count);
    for (size_t i = 0; i < count; ++i)
        pathObjs.emplace_back(GoHandle(paths[i]));

    self->refresh(pathObjs);
}

void PathSelector::cbPathDown(uintptr_t pf, uintptr_t pi, uintptr_t user)
{
    auto self = reinterpret_cast<PathSelector*>(user);
    self->pathDown(PathFingerprint(GoHandle(pf)), PathInterface(GoHandle(pi)));
}

void PathSelector::cbClose(uintptr_t user)
{
    auto self = reinterpret_cast<PathSelector*>(user);
    self->close();
}

///////////////////
// ReplySelector //
///////////////////

DLLEXPORT
ReplySelector::ReplySelector()
{
    struct PanReplySelCallbacks callbacks = {
        &ReplySelector::cbPath,
        &ReplySelector::cbInitialize,
        &ReplySelector::cbRecord,
        &ReplySelector::cbPathDown,
        &ReplySelector::cbClose
    };
    h.reset(PanNewCReplySelector(&callbacks, reinterpret_cast<uintptr_t>(this)));
}

PanPath ReplySelector::cbPath(uintptr_t remote, uintptr_t user)
{
    auto self = reinterpret_cast<ReplySelector*>(user);
    return self->path(udp::Endpoint(GoHandle(remote))).releaseHandle();
}

void ReplySelector::cbInitialize(uintptr_t local, uintptr_t user)
{
    auto self = reinterpret_cast<ReplySelector*>(user);
    self->initialize(udp::Endpoint(GoHandle(local)));
}

void ReplySelector::cbRecord(uintptr_t remote, uintptr_t path, uintptr_t user)
{
    auto self = reinterpret_cast<ReplySelector*>(user);
    self->record(
        udp::Endpoint(GoHandle(remote)),
        Path(GoHandle(path)));
}

void ReplySelector::cbPathDown(uintptr_t pf, uintptr_t pi, uintptr_t user)
{
    auto self = reinterpret_cast<ReplySelector*>(user);
    self->pathDown(
        PathFingerprint(GoHandle(pf)),
        PathInterface(GoHandle(pi)));
}

void ReplySelector::cbClose(uintptr_t user)
{
    auto self = reinterpret_cast<ReplySelector*>(user);
    self->close();
}


namespace udp {

//////////////
// Endpoint //
//////////////

DLLEXPORT
Endpoint resolveUDPAddr(const char* address)
{
    GoHandle h;
    PanError err = PanResolveUDPAddr(address, h.resetAndGetAddressOf());
    if (err) throw Exception(err);
    return Endpoint(std::move(h));
}

DLLEXPORT
Endpoint resolveUDPAddr(const char* address, std::error_code &ec) noexcept
{
    GoHandle h;
    PanError err = PanResolveUDPAddr(address, h.resetAndGetAddressOf());
    ec = make_error_code(err);
    return Endpoint(std::move(h));
}

DLLEXPORT
Endpoint::Endpoint(IA ia, const asio::ip::address &ip, std::uint16_t port)
{
    if (ip.is_v4()) {
        auto bytes = ip.to_v4().to_bytes();
        h.reset(PanUDPAddrNew(&ia, bytes.data(), bytes.size(), port));
    } else {
        auto bytes = ip.to_v6().to_bytes();
        h.reset(PanUDPAddrNew(&ia, bytes.data(), bytes.size(), port));
    }
}

DLLEXPORT
IA Endpoint::getIA() const
{
    IA ia;
    PanUDPAddrGetIA(h.get(), &ia);
    return ia;
}

DLLEXPORT
asio::ip::address Endpoint::getIP() const
{
    if (PanUDPAddrIsIPv6(h.get())) {
        asio::ip::address_v6::bytes_type bytes = {};
        PanUDPAddrGetIPv6(h.get(), bytes.data());
        return asio::ip::address_v6(bytes);
    } else {
        asio::ip::address_v4::bytes_type bytes = {};
        PanUDPAddrGetIPv4(h.get(), bytes.data());
        return asio::ip::address_v4(bytes);
    }
}

DLLEXPORT
std::uint16_t Endpoint::getPort() const
{
    return PanUDPAddrGetPort(h.get());
}

DLLEXPORT
std::string Endpoint::toString() const
{
    return CString(PanUDPAddrToString(h.get())).get();
}

///////////////////////
// ListenSockAdapter //
///////////////////////

#ifdef UNIX_DGRAM_AVAILABLE
DLLEXPORT
ListenSockAdapter::ListenSockAdapter(GoHandle handle) noexcept
    : h(std::move(handle))
{}

DLLEXPORT
void ListenSockAdapter::close() noexcept
{
    if (h) {
        PanListenSockAdapterClose(h.get());
        h.reset();
    }
}
#endif // UNIX_DGRAM_AVAILABLE

////////////////////////
// ListenSSockAdapter //
////////////////////////

#ifdef UNIX_STREAM_AVAILABLE
DLLEXPORT
ListenSSockAdapter::ListenSSockAdapter(GoHandle handle) noexcept
    : h(std::move(handle))
{}

DLLEXPORT
void ListenSSockAdapter::close() noexcept
{
    if (h) {
        PanListenSSockAdapterClose(h.get());
        h.reset();
    }
}
#endif // UNIX_STREAM_AVAILABLE

////////////////
// ListenConn //
////////////////

DLLEXPORT
ListenConn::ListenConn(std::unique_ptr<ReplySelector> sel) noexcept
    : selector(std::move(sel))
{}

DLLEXPORT
ListenConn::ListenConn(const char *bind, std::unique_ptr<ReplySelector> sel)
    : selector(std::move(sel))
{
    listen(bind);
}

DLLEXPORT
ListenConn::ListenConn(
    const char *bind, std::unique_ptr<ReplySelector> sel, std::error_code &ec
) noexcept
    : selector(std::move(sel))
{
    listen(bind, ec);
}

DLLEXPORT
void ListenConn::listen(const char *bind)
{
    PanError err = PanListenUDP(bind,
        selector ? selector->getHandle() : PAN_INVALID_HANDLE,
        h.resetAndGetAddressOf());
    if (err) throw Exception(err);
}

DLLEXPORT
void ListenConn::listen(const char *bind, std::error_code &ec) noexcept
{
    PanError err = PanListenUDP(bind,
        selector ? selector->getHandle() : PAN_INVALID_HANDLE,
        h.resetAndGetAddressOf());
    ec = make_error_code(err);
}

DLLEXPORT
void ListenConn::close() noexcept
{
    if (h) {
        PanListenConnClose(h.get());
        h.reset();
    }
}

DLLEXPORT
Endpoint ListenConn::getLocalEndpoint() const
{
    return Endpoint(GoHandle(PanListenConnLocalAddr(h.get())));
}

DLLEXPORT
void ListenConn::setDeadline(std::chrono::milliseconds t)
{
    PanListenConnSetDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
void ListenConn::setReadDeadline(std::chrono::milliseconds t)
{
    PanListenConnSetReadDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
void ListenConn::setWriteDeadline(std::chrono::milliseconds t)
{
    PanListenConnSetWriteDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
std::size_t ListenConn::readFrom(asio::mutable_buffer buffer, Endpoint *from)
{
    GoHandle hfrom;
    int n = 0;
    PanError err = PanListenConnReadFrom(h.get(), buffer.data(), buffer.size(),
        hfrom.resetAndGetAddressOf(), &n);

    if (err) throw Exception(err);

    if (from) *from = Endpoint(std::move(hfrom));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::readFrom(
    asio::mutable_buffer buffer, Endpoint *from, std::error_code &ec) noexcept
{
    GoHandle hfrom;
    int n = 0;
    PanError err = PanListenConnReadFrom(h.get(), buffer.data(), buffer.size(),
        hfrom.resetAndGetAddressOf(), &n);

    ec = make_error_code(err);
    if (err) return 0;

    if (from) *from = Endpoint(std::move(hfrom));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::readFromVia(
    asio::mutable_buffer buffer, Endpoint *from, Path *path)
{
    GoHandle hfrom, hpath;
    int n = 0;
    PanError err = PanListenConnReadFromVia(h.get(), buffer.data(), buffer.size(),
        hfrom.resetAndGetAddressOf(), hpath.resetAndGetAddressOf(), &n);

    if (err) throw Exception(err);

    if (from) *from = Endpoint(std::move(hfrom));
    if (path) *path = Path(std::move(hpath));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::readFromVia(
    asio::mutable_buffer buffer, Endpoint *from, Path *path, std::error_code &ec) noexcept
{
    GoHandle hfrom, hpath;
    int n = 0;
    PanError err = PanListenConnReadFromVia(h.get(), buffer.data(), buffer.size(),
        hfrom.resetAndGetAddressOf(), hpath.resetAndGetAddressOf(), &n);

    ec = make_error_code(err);
    if (err) return 0;

    if (from) *from = Endpoint(std::move(hfrom));
    if (path) *path = Path(std::move(hpath));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::writeTo(asio::const_buffer buffer, const Endpoint &to)
{
    int n = 0;
    PanError err = PanListenConnWriteTo(h.get(), buffer.data(), buffer.size(), to.getHandle(), &n);
    if (err) throw Exception(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::writeTo(
    asio::const_buffer buffer, const Endpoint &to, std::error_code &ec) noexcept
{
    int n = 0;
    PanError err = PanListenConnWriteTo(h.get(), buffer.data(), buffer.size(), to.getHandle(), &n);
    ec = make_error_code(err);
    if (err) return 0;
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::writeToVia(
    asio::const_buffer buffer, const Endpoint &to, const Path &path)
{
    int n = 0;
    PanError err = PanListenConnWriteToVia(
        h.get(), buffer.data(), buffer.size(), to.getHandle(), path.getHandle(), &n);
    if (err) throw Exception(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t ListenConn::writeToVia(
    asio::const_buffer buffer, const Endpoint &to, const Path &path, std::error_code &ec) noexcept
{
    int n = 0;
    PanError err = PanListenConnWriteToVia(
        h.get(), buffer.data(), buffer.size(), to.getHandle(), path.getHandle(), &n);
    ec = make_error_code(err);
    if (err) return 0;
    return static_cast<size_t>(n);
}

#ifdef UNIX_DGRAM_AVAILABLE
DLLEXPORT
ListenSockAdapter ListenConn::createSockAdapter(const char* goSocketPath, const char* cSocketPath)
{
    GoHandle handle;
    PanError err = PanNewListenSockAdapter(
        h.get(), goSocketPath, cSocketPath, handle.resetAndGetAddressOf());
    if (err) throw Exception(err);
    return ListenSockAdapter(std::move(handle));
}

DLLEXPORT
ListenSockAdapter ListenConn::createSockAdapter(
    const char* goSocketPath, const char* cSocketPath, std::error_code &ec) noexcept
{
    GoHandle handle;
    PanError err = PanNewListenSockAdapter(
        h.get(), goSocketPath, cSocketPath, handle.resetAndGetAddressOf());
    ec = make_error_code(err);
    return ListenSockAdapter(std::move(handle));
}
#endif // UNIX_DGRAM_AVAILABLE

#ifdef UNIX_STREAM_AVAILABLE
DLLEXPORT
ListenSSockAdapter ListenConn::createSSockAdapter(const char* goSocketPath)
{
    GoHandle handle;
    PanError err = PanNewListenSSockAdapter(
        h.get(), goSocketPath, handle.resetAndGetAddressOf());
    if (err) throw Exception(err);
    return ListenSSockAdapter(std::move(handle));
}

DLLEXPORT
ListenSSockAdapter ListenConn::createSSockAdapter(
    const char* goSocketPath, std::error_code &ec) noexcept
{
    GoHandle handle;
    PanError err = PanNewListenSSockAdapter(
        h.get(), goSocketPath, handle.resetAndGetAddressOf());
    ec = make_error_code(err);
    return ListenSSockAdapter(std::move(handle));
}
#endif // UNIX_STREAM_AVAILABLE

/////////////////////
// ConnSockAdapter //
/////////////////////

#ifdef UNIX_DGRAM_AVAILABLE
DLLEXPORT
ConnSockAdapter::ConnSockAdapter(GoHandle handle) noexcept
    : h(std::move(handle))
{}

DLLEXPORT
void ConnSockAdapter::close() noexcept
{
    if (h) {
        PanConnSockAdapterClose(h.get());
        h.reset();
    }
}
#endif // UNIX_DGRAM_AVAILABLE

//////////////////////
// ConnSSockAdapter //
//////////////////////

#ifdef UNIX_STREAM_AVAILABLE
DLLEXPORT
ConnSSockAdapter::ConnSSockAdapter(GoHandle handle) noexcept
    : h(std::move(handle))
{}

DLLEXPORT
void ConnSSockAdapter::close() noexcept
{
    if (h) {
        PanConnSSockAdapterClose(h.get());
        h.reset();
    }
}
#endif // UNIX_STREAM_AVAILABLE

//////////
// Conn //
//////////

DLLEXPORT
Conn::Conn(std::unique_ptr<PathPolicy> pol, std::unique_ptr<PathSelector> sel) noexcept
    : policy(std::move(pol)), selector(std::move(sel))
{}

DLLEXPORT
Conn::Conn(const char *local, const Endpoint &remote,
           std::unique_ptr<PathPolicy> pol, std::unique_ptr<PathSelector> sel)
    : policy(std::move(pol)), selector(std::move(sel))
{
    dial(local, remote);
}

DLLEXPORT
Conn::Conn(const char *local, const Endpoint &remote,
    std::unique_ptr<PathPolicy> pol, std::unique_ptr<PathSelector> sel,
    std::error_code &ec
) noexcept
    : policy(std::move(pol)), selector(std::move(sel))
{
    dial(local, remote, ec);
}

DLLEXPORT
void Conn::dial(const char *local, const Endpoint &remote)
{
    PanError err = PanDialUDP(local, remote.getHandle(),
        policy ? policy->getHandle() : PAN_INVALID_HANDLE,
        selector ? selector->getHandle() : PAN_INVALID_HANDLE,
        h.resetAndGetAddressOf());
    if (err) throw Exception(err);
}

DLLEXPORT
void Conn::dial(const char *local, const Endpoint &remote, std::error_code &ec) noexcept
{
    PanError err = PanDialUDP(local, remote.getHandle(),
        policy ? policy->getHandle() : PAN_INVALID_HANDLE,
        selector ? selector->getHandle() : PAN_INVALID_HANDLE,
        h.resetAndGetAddressOf());
    ec = make_error_code(err);
}

DLLEXPORT
void Conn::close() noexcept
{
    if (h) {
        PanConnClose(h.get());
        h.reset();
    }
}

DLLEXPORT
Endpoint Conn::getLocalEndpoint() const
{
    return Endpoint(GoHandle(PanConnLocalAddr(h.get())));
}

DLLEXPORT
Endpoint Conn::getRemoteEndpoint() const
{
    return Endpoint(GoHandle(PanConnRemoteAddr(h.get())));
}

DLLEXPORT
void Conn::setDeadline(std::chrono::milliseconds t)
{
    PanConnSetDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
void Conn::setReadDeadline(std::chrono::milliseconds t)
{
    PanConnSetReadDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
void Conn::setWriteDeadline(std::chrono::milliseconds t)
{
    PanConnSetWriteDeadline(h.get(), static_cast<uint32_t>(t.count()));
}

DLLEXPORT
std::size_t Conn::read(asio::mutable_buffer buffer)
{
    int n = 0;
    PanError err = PanConnRead(h.get(), buffer.data(), buffer.size(), &n);
    if (err) throw Exception(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::read(asio::mutable_buffer buffer, std::error_code &ec) noexcept
{
    int n = 0;
    PanError err = PanConnRead(h.get(), buffer.data(), buffer.size(), &n);
    ec = make_error_code(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::readVia(asio::mutable_buffer buffer, Path *path)
{
    GoHandle hpath;
    int n = 0;
    PanError err = PanConnReadVia(h.get(), buffer.data(), buffer.size(),
        hpath.resetAndGetAddressOf(), &n);

    if (err) throw Exception(err);

    if (path) *path = Path(std::move(hpath));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::readVia(
    asio::mutable_buffer buffer, Path *path, std::error_code &ec) noexcept
{
    GoHandle hpath;
    int n = 0;
    PanError err = PanConnReadVia(h.get(), buffer.data(), buffer.size(),
        hpath.resetAndGetAddressOf(), &n);

    ec = make_error_code(err);

    if (path) *path = Path(std::move(hpath));
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::write(asio::const_buffer buffer)
{
    int n = 0;
    PanError err = PanConnWrite(h.get(), buffer.data(), buffer.size(), &n);
    if (err) throw Exception(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::write(asio::const_buffer buffer, std::error_code &ec) noexcept
{
    int n = 0;
    PanError err = PanConnWrite(h.get(), buffer.data(), buffer.size(), &n);
    ec = make_error_code(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::writeVia(asio::const_buffer buffer, const Path &path)
{
    int n = 0;
    PanError err = PanConnWriteVia(
        h.get(), buffer.data(), buffer.size(), path.getHandle(), &n);
    if (err) throw Exception(err);
    return static_cast<size_t>(n);
}

DLLEXPORT
std::size_t Conn::writeVia(
    asio::const_buffer buffer, const Path &path, std::error_code &ec) noexcept
{
    int n = 0;
    PanError err = PanConnWriteVia(
        h.get(), buffer.data(), buffer.size(), path.getHandle(), &n);
    ec = make_error_code(err);
    return static_cast<size_t>(n);
}

#ifdef UNIX_DGRAM_AVAILABLE
DLLEXPORT
ConnSockAdapter Conn::createSockAdapter(const char *goSocketPath, const char *cSocketPath)
{
    GoHandle handle;
    PanError err = PanNewConnSockAdapter(
        h.get(), goSocketPath, cSocketPath, handle.resetAndGetAddressOf());
    if (err) throw Exception(err);
    return ConnSockAdapter(std::move(handle));
}

DLLEXPORT
ConnSockAdapter Conn::createSockAdapter(const char *goSocketPath, const char *cSocketPath, std::error_code &ec) noexcept
{
    GoHandle handle;
    PanError err = PanNewConnSockAdapter(
        h.get(), goSocketPath, cSocketPath, handle.resetAndGetAddressOf());
    ec = make_error_code(err);
    return ConnSockAdapter(std::move(handle));
}
#endif // UNIX_DGRAM_AVAILABLE

#ifdef UNIX_STREAM_AVAILABLE
DLLEXPORT
ConnSSockAdapter Conn::createSSockAdapter(const char *goSocketPath)
{
    GoHandle handle;
    PanError err = PanNewConnSSockAdapter(
        h.get(), goSocketPath, handle.resetAndGetAddressOf());
    if (err) throw Exception(err);
    return ConnSSockAdapter(std::move(handle));
}

DLLEXPORT
ConnSSockAdapter Conn::createSSockAdapter(const char *goSocketPath, std::error_code &ec) noexcept
{
    GoHandle handle;
    PanError err = PanNewConnSSockAdapter(
        h.get(), goSocketPath, handle.resetAndGetAddressOf());
    ec = make_error_code(err);
    return ConnSSockAdapter(std::move(handle));
}
#endif // UNIX_STREAM_AVAILABLE

} // namespace udp
} // namespace Pan
