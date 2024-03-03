/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package github.com/lschulz/libpan/go */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 17 "pan_wrapper.go"

 #include "pan/pan_cdefs.h"
 #define PAN_STREAM_HDR_SIZE 4
 #define PAN_ADDR_HDR_SIZE 32
 /** \file
	* PAN C Wrapper
  * \defgroup handle Go Handles
  * \defgroup addresses Addresses
  * Functions for working with IP and SCION addresses.
  * \defgroup path Path
  * SCION path related functions.
  * \defgroup path_fingerprint Path Fingerprint
  * \defgroup policy Path Policy
  * \defgroup selector Path Selector
  * \defgroup reply_selector Reply Selector
  * \defgroup listen_conn ListenConn
  * PAN ListenConn methods.
  * \defgroup conn Conn
  * PAN Conn methods.
  * \defgroup adapter Socket Adapter
  * UNIX domain socket adapter.
  */

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


/**
\brief Duplicate a cgo handle.
\ingroup handle
*/
extern uintptr_t PanDuplicateHandle(uintptr_t handle);

/**
\brief Delete a handle obtained from cgo.
\ingroup handle
*/
extern void PanDeleteHandle(uintptr_t handle);

/**
\brief Wrapper for `pan.ResolveUDPAddr`
	A handle to the resolved address is returned in `resolved`.
\ingroup addresses
*/
extern PanError PanResolveUDPAddr(cchar_t* address, PanUDPAddr* resolved);

/**
\brief Create a PanUDPAddr from ISD, ASN, IP and UDP port.
\param[in] ia Pointer to the ISD and AS number packed as 8 bytes in big-endian
	byte order. Must not be NULL.
\param[in] ip Pointer to the IP address in big-endian byte order. Must not be
	NULL.
\param[in] ip_len Length of the IP address in bytes. Must be 4 or 16.
\param[in] port UDP port number
\return UDPAddr handle. A null handle is returned if \p ip_len is not 4 or 16.
\ingroup addresses
*/
extern PanUDPAddr PanUDPAddrNew(cuint64_t* ia, cuint8_t* ip, int ip_len, uint16_t port);

/**
\brief Get the ISD (2 bytes) and ASN (6 bytes) of the address.
\param[out] Pointer to 8 bytes that will receive the ISD and AS number in
	big-endian byte order. Function is a no-op if this is `NULL`.
\ingroup addresses
*/
extern void PanUDPAddrGetIA(PanUDPAddr addr, uint64_t* ia);

/**
\brief Returns whether the IP-part of the address is IPv6 (including mapped IPv4
	addresses).
\return `0` for IPv4 addresses, non-zero otherwise.
\ingroup addresses
*/
extern int PanUDPAddrIsIPv6(PanUDPAddr addr);

/**
\brief Get the IP part of the address. Fails if the address is not an IPv4
	or IPv4-in-IPv6 address.
\param[out] ipv4 Pointer to a 4-byte array that will receive the IP address.
	Function is a no-op if this is `NULL`.
\return `PAN_ERR_OK` if no error occurred.
	`PAN_ERR_FAILED` if the address cannot be represented in 4 bytes.
\ingroup addresses
*/
extern PanError PanUDPAddrGetIPv4(PanUDPAddr addr, uint8_t* ip4);

/**
\brief Get the IP part of the address. IPv4 addresses are returned in
	IPv6-mapped form.
\param[out] ipv6 Pointer to a 16-byte array that will receive the IP address.
	Function is a no-op if this is `NULL`.
\return `PAN_ERR_OK` if no error occurred.
\ingroup addresses
*/
extern PanError PanUDPAddrGetIPv6(PanUDPAddr addr, uint8_t* ip6);

/**
\brief Get the UDP port as integer in host byte order.
\ingroup addresses
*/
extern uint16_t PanUDPAddrGetPort(PanUDPAddr addr);

/**
\brief Returns a string representation of the given SCION address.
The returned string must be freed with free().
\ingroup addresses
*/
extern char* PanUDPAddrToString(PanUDPAddr addr);

/**
\brief Return a string representing the path.
The returned string must be freed with free().
\ingroup path
*/
extern char* PanPathToString(PanPath path);

/**
\brief Get the fingerprint of the path.
\ingroup path
*/
extern PanPathFingerprint PanPathGetFingerprint(PanPath path);

/**
\brief Check whether a path contains a certain AS interface.
\ingroup path
*/
extern int PanPathContainsInterface(PanPath path, PanPathInterface iface);

/**
\brief Check whether two path fingerprints compare equal.
\ingroup path_fingerprint
*/
extern int PanPathFingerprintAreEqual(PanPathFingerprint fp_a, PanPathFingerprint fp_b);

/**
\brief Create a new path policy from a filter function.
\param[in] filter Filter callback.
\param[in] user User data that will be passed to the callback.
\ingroup policy
*/
extern PanPolicy PanNewCPolicy(PanPolicyFilterFn filter, uintptr_t user);

/**
\brief Create a new path selector.
\param[in] callbacks Callbacks for the methods of the path selector.
\param[in] user User data that will be passed to the callback.
\ingroup selector
*/
extern PanSelector PanNewCSelector(struct PanSelectorCallbacks* callbacks, uintptr_t user);

/**
\brief Create a new reply selector.
\param[in] callbacks Callbacks for the methods of the reply selector.
\param[in] user User data that will be passed to the callback.
\ingroup reply_selector
*/
extern PanReplySelector PanNewCReplySelector(struct PanReplySelCallbacks* callbacks, uintptr_t user);

/**
\brief Open a UDP socket and listen for connections.
\param[in] listen is the local IP and port to listen on as a null-terminated
	string (e.g., "127.0.0.1:8000").
\param[in] selector Reply path selector. May be a PAN_INVALID_HANDLE to use the
	default selector.
\param[out] conn The value pointed to by \p conn receives the listening
	connection handle if the call is successful.
	\ingroup listen_conn
\return `PAN_ERR_OK` on success.
	`PAN_ERR_ADDR_SYNTAX` is the listen address has an invalid format.
	`PAN_ERR_FAILED` if binding and listening on the socket failed.
*/
extern PanError PanListenUDP(cchar_t* listen, PanReplySelector selector, PanListenConn* conn);

/**
\brief Wrapper for `(pan.ListenConn).ReadFrom`
\param[in] conn Listening connection.
\param[in] buffer Pointer to a buffer that will receive the packet.
\param[in] len Size of \p buffer in bytes.
\param[out] from Host from which data was received. Can be NULL to ignore.
\param[out] n Number of bytes read. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup listen_conn
*/
extern PanError PanListenConnReadFrom(PanListenConn conn, void* buffer, int len, PanUDPAddr* from, int* n);

/**
\brief Wrapper for `(pan.ListenConn).ReadFromVia`
\param[in] conn Listening connection.
\param[in] buffer Pointer to a buffer that will receive the packet.
\param[in] len Size of \p buffer in bytes.
\param[out] from Host from which data was received. Can be NULL to ignore.
\param[out] path Path of the received packet. Can be NULL to ignore.
\param[out] n Number of bytes read. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup listen_conn
*/
extern PanError PanListenConnReadFromVia(PanListenConn conn, void* buffer, int len, PanUDPAddr* from, PanPath* path, int* n);

/**
\briefWrapper for `(pan.ListenConn).WriteTo`
\param[in] conn Listening connection.
\param[in] buffer Pointer to a buffer containing the message.
\param[in] len Length of the message in \p buffer in bytes.
\param[in] to Destination address.
\param[out] n Number of bytes written. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_NO_PATH` if no path to the destination is known.
	`PAN_ERR_FAILED` if the operation failed in some other way.
\ingroup listen_conn
*/
extern PanError PanListenConnWriteTo(PanListenConn conn, cvoid_t* buffer, int len, PanUDPAddr to, int* n);

/**
\brief Wrapper for `(pan.ListenConn).WriteToVia`
\param[in] conn Listening connection.
\param[in] buffer Pointer to a buffer containing the message.
\param[in] len Length of the message in \p buffer in bytes.
\param[in] to Destination address.
\param[in] path Path to take to the destination.
\param[out] n Number of bytes written. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup listen_conn
*/
extern PanError PanListenConnWriteToVia(PanListenConn conn, cvoid_t* buffer, int len, PanUDPAddr to, PanPath path, int* n);

/**
\brief Wrapper for `(pan.ListenConn).LocalAddr`
\ingroup listen_conn
*/
extern PanUDPAddr PanListenConnLocalAddr(PanListenConn conn);

/**
\brief Wrapper for `(pan.ListenConn).SetDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
extern PanError PanListenConnSetDeadline(PanListenConn conn, uint32_t t);

/**
\brief Wrapper for `(pan.ListenConn).SetReadDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
extern PanError PanListenConnSetReadDeadline(PanListenConn conn, uint32_t t);

/**
\brief Wrapper for `(pan.ListenConn).SetWriteDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
extern PanError PanListenConnSetWriteDeadline(PanListenConn conn, uint32_t t);

/**
\brief Close a listening socket. The handle must still be deleted with
PanDeleteHandle().
\ingroup listen_conn
*/
extern PanError PanListenConnClose(PanListenConn conn);

/**
\brief Wrapper for `pan.DialUDP`
\param[in] local is the local IP and port as string. Can be NULL to automatically
	choose.
\param[in] remote is the SCION address of the remote host.
\param[in] policy Path policy. May be a PAN_INVALID_HANDLE to use the default
	policy.
\param[in] selector Path selector. May be a PAN_INVALID_HANDLE to use the
	default selector.
\param[out] conn The value pointed to by \p conn receives the connection handle
	if the call is successful.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_ADDR_SYNTAX` is the local address has an invalid format.
	`PAN_ERR_FAILED` if dialing failed.
\ingroup conn
*/
extern PanError PanDialUDP(cchar_t* local, PanUDPAddr remote, PanPolicy policy, PanSelector selector, PanConn* conn);

/**
\brief Wrapper for `(pan.Conn).Read`
\param[in] conn Connection
\param[in] buffer Pointer to a buffer that will receive the packet.
\param[in] len Size of \p buffer in bytes.
\param[out] n Number of bytes read. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup conn
*/
extern PanError PanConnRead(PanConn conn, void* buffer, int len, int* n);

/**
\brief Wrapper for `(pan.Conn).ReadVia`
\param[in] conn Connection
\param[in] buffer Pointer to a buffer that will receive the packet.
\param[in] len Size of \p buffer in bytes.
\param[out] path Path of the received packet. Can be NULL to ignore.
\param[out] n Number of bytes read. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup conn
*/
extern PanError PanConnReadVia(PanConn conn, void* buffer, int len, PanPath* path, int* n);

/**
\brief Wrapper for `(pan.Conn).Write`
\param[in] conn Connection
\param[in] buffer Pointer to a buffer containing the message.
\param[in] len Length of the message in \p buffer in bytes.
\param[out] n Number of bytes written. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_NO_PATH` if no path to the destination is known.
	`PAN_ERR_FAILED` if the operation failed in some other way.
\ingroup conn
*/
extern PanError PanConnWrite(PanListenConn conn, cvoid_t* buffer, int len, int* n);

/**
\brief Wrapper for `(pan.Conn).WriteVia`
\param[in] conn Connection
\param[in] buffer Pointer to a buffer containing the message.
\param[in] len Length of the message in \p buffer in bytes.
\param[in] path Path to take to the destination.
\param[out] n Number of bytes written. Can be NULL to ignore.
\return `PAN_ERR_OK` on success.
	`PAN_ERR_DEADLINE` if the deadline was exceeded.
	`PAN_ERR_FAILED` if the operation failed.
\ingroup conn
*/
extern PanError PanConnWriteVia(PanListenConn conn, cvoid_t* buffer, int len, PanPath path, int* n);

/**
\brief Wrapper for (pan.Conn).LocalAddr
\ingroup conn
*/
extern PanUDPAddr PanConnLocalAddr(PanConn conn);

/**
\brief Wrapper for `(pan.Conn).RemoteAddr`
\ingroup conn
*/
extern PanUDPAddr PanConnRemoteAddr(PanConn conn);

/**
\brief Wrapper for `(pan.Conn).SetDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
extern PanError PanConnSetDeadline(PanConn conn, uint32_t t);

/**
\brief Wrapper for `(pan.Conn).SetReadDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
extern PanError PanConnSetReadDeadline(PanConn conn, uint32_t t);

/**
\brief Wrapper for `(pan.Conn).SetWriteDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
extern PanError PanConnSetWriteDeadline(PanConn conn, uint32_t t);

/**
\brief Close a connection. The handle must still be deleted with
PanDeleteHandle().
\ingroup conn
*/
extern PanError PanConnClose(PanConn conn);

/**
\brief Open a Unix datagram socket at `listen_addr` as proxy for `pan_conn`.

All packets received by `pan_conn` are forwarded from `listen_addr` to `client_addr`.
All packets received from the Unix socket are forwarded to `pan_conn`.
The SCION address of the source or destination is prepended to the payload in a
32 byte header:
\verbatim
byte 0       1       2       3       4       5       6       7
     +-------+-------+-------+-------+-------+-------+-------+-------+
   0 |    ISD (BE)   |                     ASN (BE)                  |
     +-------+-------+-------+-------+-------+-------+-------+-------+
   8 |    Host Addr. Length (LE)     |                               |
     +-------+-------+-------+-------+                               |
  16 |                         Host Address (BE)                     |
     +                               +-------+-------+-------+-------+
  24 |                               | UDP Port (LE) |       0       |
     +-------+-------+-------+-------+-------+-------+-------+-------+
BE = big-endian
LE = little-endian
\endverbatim

\param[in] pan_conn Listening PAN connection.
\param[in] listen_addr Local address of the socket in the file system.
\param[in] client_addr Address of the other end of the connection in the C part
	of the program.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
extern PanError PanNewListenSockAdapter(PanListenConn pan_conn, cchar_t* listen_addr, cchar_t* client_addr, PanListenSockAdapter* adapter);

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
extern PanError PanListenSockAdapterClose(PanListenSockAdapter adapter);

/**
\brief Open a Unix datagram socket at `listen_addr` as proxy for `pan_conn`.

All packets received by pan_conn are forwarded from `listen_addr` to `client_addr`.
All packets received from the unix socket are forwarded to `pan_conn`.

\param[in] pan_conn Connected PAN connection.
\param[in] listen_addr Local address of the unix socket in the file system.
\param[in] client_addr Address of the other end of the connection in the C part
	of the program.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
extern PanError PanNewConnSockAdapter(PanConn pan_conn, cchar_t* listen_addr, cchar_t* client_addr, PanConnSockAdapter* adapter);

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
extern PanError PanConnSockAdapterClose(PanConnSockAdapter adapter);

/**
\brief Open a Unix stream socket at `listen_addr` as proxy for `pan_conn`.

Behaves identical to `PanNewListenSockAdapter` except that a stream socket is
used instead of a datagram socket. Packet borders in the stream are determined
by prepending a four byte message length (little endian) in front of every
packet sent or received on the Unix socket.

When initially created, the socket will listens for and accept exactly one
connection.

The stream variants of the socket adapters are intended for systems lacking
support for Unix datagram sockets, e.g., Windows. A more native solution on
Windows might be named pipes, however they have a very different API from
sockets.

\param[in] pan_conn Listening PAN connection.
\param[in] listen_addr Local address of the socket in the file system.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
extern PanError PanNewListenSSockAdapter(PanListenConn pan_conn, cchar_t* listen_addr, PanListenSSockAdapter* adapter);

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
extern PanError PanListenSSockAdapterClose(PanListenSSockAdapter adapter);

/**
\brief Open a Unix stream socket at `listen_addr` as proxy for `pan_conn`.

Behaves identical to `PanNewConnSockAdapter` except that a stream socket is
used instead of a datagram socket. Packet borders in the stream are determined
by prepending a four byte message length (little endian) in front of every
packet sent or received on the Unix socket.

When initially created, the socket will listens for and accept exactly one
connection.

The stream variants of the socket adapters are intended for systems lacking
support for Unix datagram sockets, e.g., Windows. A more native solution on
Windows might be named pipes, however they have a very different API from
sockets.

\param[in] pan_conn Connected PAN connection.
\param[in] listen_addr Local address of the Unix socket in the file system.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
extern PanError PanNewConnSSockAdapter(PanConn pan_conn, cchar_t* listen_addr, PanConnSSockAdapter* adapter);

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
extern PanError PanConnSSockAdapterClose(PanConnSSockAdapter adapter);

#ifdef __cplusplus
}
#endif
