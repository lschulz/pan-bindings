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

package main

// #cgo CFLAGS: -I../include
// #include "pan_cdefs.h"
// #define PAN_ADDR_HDR_SIZE 32
// /** \file
//	* PAN C Wrapper
//  * \defgroup handle Go Handles
//  * \defgroup addresses Addresses
//  * Functions for working with IP and SCION addresses.
//  * \defgroup path Path
//  * SCION path related functions.
//  * \defgroup path_fingerprint Path Fingerprint
//  * \defgroup policy Path Policy
//  * \defgroup selector Path Selector
//  * \defgroup reply_selector Reply Selector
//  * \defgroup listen_conn ListenConn
//  * PAN ListenConn methods.
//  * \defgroup conn Conn
//  * PAN Conn methods.
//  * \defgroup adapter Socket Adapter
//  * UNIX domain socket adapter.
//  */
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"inet.af/netaddr"
)

const ADDR_HDR_SIZE = 32

/**
\brief Duplicate a cgo handle.
\ingroup handle
*/
//export PanDuplicateHandle
func PanDuplicateHandle(handle C.uintptr_t) C.uintptr_t {
	return C.uintptr_t(cgo.NewHandle(cgo.Handle(handle).Value()))
}

/**
\brief Delete a handle obtained from cgo.
\ingroup handle
*/
//export PanDeleteHandle
func PanDeleteHandle(handle C.uintptr_t) {
	h := cgo.Handle(handle)
	h.Delete()
}

///////////////
// Addresses //
///////////////

/**
\brief Wrapper for `pan.ResolveUDPAddr`
	A handle to the resolved address is returned in `resolved`.
\ingroup addresses
*/
//export PanResolveUDPAddr
func PanResolveUDPAddr(address *C.cchar_t, resolved *C.PanUDPAddr) C.PanError {
	addr, err := pan.ResolveUDPAddr(context.Background(), C.GoString(address))
	if err != nil {
		return C.PAN_ERR_ADDR_RESOLUTION
	}
	ptr := (*C.PanUDPAddr)(unsafe.Pointer(resolved))
	*ptr = C.PanUDPAddr(cgo.NewHandle(addr))
	return C.PAN_ERR_OK
}

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
//export PanUDPAddrNew
func PanUDPAddrNew(ia *C.cuint64_t, ip *C.cuint8_t, ip_len C.int, port C.uint16_t) C.PanUDPAddr {
	var addr pan.UDPAddr

	// IA
	addr.IA = (pan.IA)(binary.BigEndian.Uint64((*[8]byte)(unsafe.Pointer(ia))[:]))

	// IP
	if ip_len == 4 {
		b := (*[4]byte)(unsafe.Pointer(ip))
		addr.IP = netaddr.IPFrom4(*b)
	} else if ip_len == 16 {
		b := (*[16]byte)(unsafe.Pointer(ip))
		addr.IP = netaddr.IPFrom16(*b)
	} else {
		return 0
	}

	// Port
	addr.Port = uint16(port)

	return C.PanUDPAddr(cgo.NewHandle(addr))
}

/**
\brief Get the ISD (2 bytes) and ASN (6 bytes) of the address.
\param[out] Pointer to 8 bytes that will receive the ISD and AS number in
	big-endian byte order. Function is a no-op if this is `NULL`.
\ingroup addresses
*/
//export PanUDPAddrGetIA
func PanUDPAddrGetIA(addr C.PanUDPAddr, ia *C.uint64_t) {
	var buf = make([]byte, 8)
	if ia != nil {
		address := cgo.Handle(addr).Value().(pan.UDPAddr)
		binary.BigEndian.PutUint64(buf, (uint64)(address.IA))
		ptr := (*[8]C.uint8_t)(unsafe.Pointer(ia))
		for i, b := range buf[:8] {
			ptr[i] = C.uint8_t(b)
		}
	}
}

/**
\brief Returns whether the IP-part of the address is IPv6 (including mapped IPv4
	addresses).
\return `0` for IPv4 addresses, non-zero otherwise.
\ingroup addresses
*/
//export PanUDPAddrIsIPv6
func PanUDPAddrIsIPv6(addr C.PanUDPAddr) C.int {
	address := cgo.Handle(addr).Value().(pan.UDPAddr)
	if address.IP.Is6() {
		return 1
	} else {
		return 0
	}
}

/**
\brief Get the IP part of the address. Fails if the address is not an IPv4
	or IPv4-in-IPv6 address.
\param[out] ipv4 Pointer to a 4-byte array that will receive the IP address.
	Function is a no-op if this is `NULL`.
\return `PAN_ERR_OK` if no error occurred.
	`PAN_ERR_FAILED` if the address cannot be represented in 4 bytes.
\ingroup addresses
*/
//export PanUDPAddrGetIPv4
func PanUDPAddrGetIPv4(addr C.PanUDPAddr, ip4 *C.uint8_t) C.PanError {
	if ip4 != nil {
		address := cgo.Handle(addr).Value().(pan.UDPAddr)
		if !address.IP.Is4() && !address.IP.Is4in6() {
			return C.PAN_ERR_FAILED
		}
		ptr := (*[4]C.uint8_t)(unsafe.Pointer(ip4))
		for i, b := range address.IP.As4() {
			ptr[i] = C.uint8_t(b)
		}
	}
	return C.PAN_ERR_OK
}

/**
\brief Get the IP part of the address. IPv4 addresses are returned in
	IPv6-mapped form.
\param[out] ipv6 Pointer to a 16-byte array that will receive the IP address.
	Function is a no-op if this is `NULL`.
\return `PAN_ERR_OK` if no error occurred.
\ingroup addresses
*/
//export PanUDPAddrGetIPv6
func PanUDPAddrGetIPv6(addr C.PanUDPAddr, ip6 *C.uint8_t) C.PanError {
	if ip6 != nil {
		address := cgo.Handle(addr).Value().(pan.UDPAddr)
		ptr := (*[16]C.uint8_t)(unsafe.Pointer(ip6))
		for i, b := range address.IP.As16() {
			ptr[i] = C.uint8_t(b)
		}
	}
	return C.PAN_ERR_OK
}

/**
\brief Get the UDP port as integer in host byte order.
\ingroup addresses
*/
//export PanUDPAddrGetPort
func PanUDPAddrGetPort(addr C.PanUDPAddr) C.uint16_t {
	address := cgo.Handle(addr).Value().(pan.UDPAddr)
	return C.uint16_t(address.Port)
}

/**
\brief Returns a string representation of the given SCION address.
The returned string must be freed with free().
\ingroup addresses
*/
//export PanUDPAddrToString
func PanUDPAddrToString(addr C.PanUDPAddr) *C.char {
	address := cgo.Handle(addr).Value().(pan.UDPAddr)
	return C.CString(address.String())
}

//////////
// Path //
//////////

/**
\brief Return a string representing the path.
The returned string must be freed with free().
\ingroup path
*/
//export PanPathToString
func PanPathToString(path C.PanPath) *C.char {
	p := cgo.Handle(path).Value().(*pan.Path)
	return C.CString(p.String())
}

/**
\brief Get the fingerprint of the path.
\ingroup path
*/
//export PanPathGetFingerprint
func PanPathGetFingerprint(path C.PanPath) C.PanPathFingerprint {
	p := cgo.Handle(path).Value().(*pan.Path)
	return (C.PanPathFingerprint)(cgo.NewHandle(p.Fingerprint))
}

/**
\brief Check whether a path contains a certain AS interface.
\ingroup path
*/
//export PanPathContainsInterface
func PanPathContainsInterface(path C.PanPath, iface C.PanPathInterface) C.int {
	p := cgo.Handle(path).Value().(*pan.Path)
	pi := cgo.Handle(iface).Value().(pan.PathInterface)
	for _, c := range p.Metadata.Interfaces {
		if c == pi {
			return 1
		}
	}
	return 0
}

// Create cgo handles for each path in the slice.
func getPathHandles(paths []*pan.Path) []C.PanPath {
	path_handles := make([]C.PanPath, len(paths))
	for i, path := range paths {
		path_handles[i] = (C.PanPath)(cgo.NewHandle(path))
	}
	return path_handles
}

// Create cgo handles for each path in the slice.
func deletePathHandles(paths []C.PanPath) {
	for _, path := range paths {
		cgo.Handle(path).Delete()
	}
}

/////////////////////
// PathFingerprint //
/////////////////////

/**
\brief Check whether two path fingerprints compare equal.
\ingroup path_fingerprint
*/
//export PanPathFingerprintAreEqual
func PanPathFingerprintAreEqual(
	fp_a C.PanPathFingerprint, fp_b C.PanPathFingerprint) C.int {
	a := cgo.Handle(fp_a).Value().(pan.PathFingerprint)
	b := cgo.Handle(fp_b).Value().(pan.PathFingerprint)
	if a == b {
		return 1
	} else {
		return 0
	}
}

////////////
// Policy //
////////////

type CPolicy struct {
	filter_cb C.PanPolicyFilterFn
	user_data C.uintptr_t
}

func NewCPolicy(filter C.PanPolicyFilterFn, user C.uintptr_t) *CPolicy {
	return &CPolicy{
		filter_cb: filter,
		user_data: user,
	}
}

func (p *CPolicy) Filter(paths []*pan.Path) []*pan.Path {
	if len(paths) == 0 {
		return paths
	}

	path_handles := getPathHandles(paths)
	all_path_handles := make([]C.PanPath, len(path_handles))
	copy(all_path_handles, path_handles)
	defer deletePathHandles(all_path_handles)

	count := len(path_handles)
	newCount := int(
		C.panCallPolicyFilter(p.filter_cb, &path_handles[0], C.size_t(count), p.user_data))

	if newCount > 0 && newCount <= count {
		filtered := make([]*pan.Path, 0, newCount)
		for _, path := range path_handles {
			filtered = append(filtered, cgo.Handle(path).Value().(*pan.Path))
		}
		return filtered
	}

	return nil
}

/**
\brief Create a new path policy from a filter function.
\param[in] filter Filter callback.
\param[in] user User data that will be passed to the callback.
\ingroup policy
*/
//export PanNewCPolicy
func PanNewCPolicy(filter C.PanPolicyFilterFn, user C.uintptr_t) C.PanPolicy {
	return (C.PanPolicy)(cgo.NewHandle(NewCPolicy(filter, user)))
}

//////////////
// Selector //
//////////////

type CSelector struct {
	callbacks C.struct_PanSelectorCallbacks
	user_data C.uintptr_t
}

func NewCSelector(callbacks *C.struct_PanSelectorCallbacks, user C.uintptr_t) *CSelector {
	return &CSelector{
		callbacks: *callbacks,
		user_data: user,
	}
}

func (s *CSelector) Path() *pan.Path {
	path := C.panCallSelectorPath(s.callbacks.path, s.user_data)
	return cgo.Handle(path).Value().(*pan.Path)
}

func (s *CSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	loc := cgo.NewHandle(local)
	rem := cgo.NewHandle(remote)
	path_handles := getPathHandles(paths)
	count := (C.size_t)(len(path_handles))
	C.panCallSelectorInitialize(
		s.callbacks.initialize, C.PanUDPAddr(loc), C.PanUDPAddr(rem),
		&path_handles[0], count, s.user_data)
}

func (s *CSelector) Refresh(paths []*pan.Path) {
	path_handles := getPathHandles(paths)
	count := (C.size_t)(len(path_handles))
	C.panCallSelectorRefresh(s.callbacks.refresh, &path_handles[0], count, s.user_data)
}

func (s *CSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	fingerprint := cgo.NewHandle(pf)
	iface := cgo.NewHandle(pf)
	C.panCallSelectorPathDown(s.callbacks.pathDown,
		(C.PanPathFingerprint)(fingerprint),
		(C.PanPathInterface)(iface),
		s.user_data)
}

func (s *CSelector) Close() error {
	C.panCallSelectorClose(s.callbacks.close, s.user_data)
	return nil
}

/**
\brief Create a new path selector.
\param[in] callbacks Callbacks for the methods of the path selector.
\param[in] user User data that will be passed to the callback.
\ingroup selector
*/
//export PanNewCSelector
func PanNewCSelector(callbacks *C.struct_PanSelectorCallbacks, user C.uintptr_t) C.PanSelector {
	return (C.PanSelector)(cgo.NewHandle(NewCSelector(callbacks, user)))
}

///////////////////
// ReplySelector //
///////////////////

type CReplySelector struct {
	callbacks C.struct_PanReplySelCallbacks
	user_data C.uintptr_t
}

func NewCReplySelector(callbacks *C.struct_PanReplySelCallbacks, user C.uintptr_t) *CReplySelector {
	return &CReplySelector{
		callbacks: *callbacks,
		user_data: user,
	}
}

func (s *CReplySelector) Path(remote pan.UDPAddr) *pan.Path {
	rem := cgo.NewHandle(remote)
	path := C.panCallReplySelPath(s.callbacks.path, C.PanUDPAddr(rem), s.user_data)
	return cgo.Handle(path).Value().(*pan.Path)
}

func (s *CReplySelector) Initialize(local pan.UDPAddr) {
	loc := cgo.NewHandle(local)
	C.panCallReplySelInitialize(s.callbacks.initialize, C.PanUDPAddr(loc), s.user_data)
}

func (s *CReplySelector) Record(remote pan.UDPAddr, path *pan.Path) {
	rem := cgo.NewHandle(remote)
	handle := cgo.NewHandle(path)
	C.panCallReplySelRecord(s.callbacks.record, C.PanUDPAddr(rem), C.PanPath(handle), s.user_data)
}

func (s *CReplySelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	fingerprint := cgo.NewHandle(pf)
	iface := cgo.NewHandle(pf)
	C.panCallReplySelPathDown(s.callbacks.pathDown,
		(C.PanPathFingerprint)(fingerprint),
		(C.PanPathInterface)(iface),
		s.user_data)
}

func (s *CReplySelector) Close() error {
	C.panCallReplySelClose(s.callbacks.close, s.user_data)
	return nil
}

/**
\brief Create a new reply selector.
\param[in] callbacks Callbacks for the methods of the reply selector.
\param[in] user User data that will be passed to the callback.
\ingroup reply_selector
*/
//export PanNewCReplySelector
func PanNewCReplySelector(
	callbacks *C.struct_PanReplySelCallbacks, user C.uintptr_t) C.PanReplySelector {
	return (C.PanReplySelector)(cgo.NewHandle(NewCReplySelector(callbacks, user)))
}

////////////////
// ListenConn //
////////////////

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
//export PanListenUDP
func PanListenUDP(
	listen *C.cchar_t, selector C.PanReplySelector, conn *C.PanListenConn) C.PanError {
	var sel pan.ReplySelector = nil

	local, err := netaddr.ParseIPPort(C.GoString(listen))
	if err != nil {
		return C.PAN_ERR_ADDR_SYNTAX
	}

	if selector != 0 {
		sel = cgo.Handle(selector).Value().(pan.ReplySelector)
	}

	c, err := pan.ListenUDP(context.Background(), local, sel)
	if err != nil {
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenConn)(unsafe.Pointer(conn))
	*ptr = C.PanListenConn(cgo.NewHandle(c))

	return C.PAN_ERR_OK
}

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
//export PanListenConnReadFrom
func PanListenConnReadFrom(
	conn C.PanListenConn, buffer *C.void, len C.int, from *C.PanUDPAddr, n *C.int) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	read, addr, err := c.ReadFrom(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if from != nil {
		*(*C.PanUDPAddr)(unsafe.Pointer(from)) = C.PanUDPAddr(cgo.NewHandle(addr))
	}
	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(read)
	}

	return C.PAN_ERR_OK
}

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
//export PanListenConnReadFromVia
func PanListenConnReadFromVia(
	conn C.PanListenConn, buffer *C.void, len C.int,
	from *C.PanUDPAddr, path *C.PanPath, n *C.int) C.PanError {

	c := cgo.Handle(conn).Value().(pan.ListenConn)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	read, addr, via, err := c.ReadFromVia(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if from != nil {
		*(*C.PanUDPAddr)(unsafe.Pointer(from)) = C.PanUDPAddr(cgo.NewHandle(addr))
	}
	if path != nil {
		*(*C.PanPath)(unsafe.Pointer(path)) = C.PanPath(cgo.NewHandle(via))
	}
	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(read)
	}

	return C.PAN_ERR_OK
}

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
//export PanListenConnWriteTo
func PanListenConnWriteTo(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, n *C.int) C.PanError {

	c := cgo.Handle(conn).Value().(pan.ListenConn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	addr := cgo.Handle(to).Value().(pan.UDPAddr)

	written, err := c.WriteTo(p, addr)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else if errors.Is(err, pan.ErrNoPath) {
			return C.PAN_ERR_NO_PATH
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(written)
	}

	return C.PAN_ERR_OK
}

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
//export PanListenConnWriteToVia
func PanListenConnWriteToVia(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int,
	to C.PanUDPAddr, path C.PanPath, n *C.int) C.PanError {

	c := cgo.Handle(conn).Value().(pan.ListenConn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	addr := cgo.Handle(to).Value().(pan.UDPAddr)
	via := cgo.Handle(path).Value().(*pan.Path)

	written, err := c.WriteToVia(p, addr, via)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(written)
	}

	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.ListenConn).LocalAddr`
\ingroup listen_conn
*/
//export PanListenConnLocalAddr
func PanListenConnLocalAddr(conn C.PanListenConn) C.PanUDPAddr {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	return C.PanUDPAddr(cgo.NewHandle(c.LocalAddr()))
}

/**
\brief Wrapper for `(pan.ListenConn).SetDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
//export PanListenConnSetDeadline
func PanListenConnSetDeadline(conn C.PanListenConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	c.SetDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.ListenConn).SetReadDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
//export PanListenConnSetReadDeadline
func PanListenConnSetReadDeadline(conn C.PanListenConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	c.SetReadDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.ListenConn).SetWriteDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
//export PanListenConnSetWriteDeadline
func PanListenConnSetWriteDeadline(conn C.PanListenConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	c.SetWriteDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Close a listening socket. The handle must still be deleted with
PanDeleteHandle().
\ingroup listen_conn
*/
//export PanListenConnClose
func PanListenConnClose(conn C.PanListenConn) C.PanError {
	handle := cgo.Handle(conn)
	err := handle.Value().(pan.ListenConn).Close()
	if err != nil {
		return C.PAN_ERR_FAILED
	}
	return C.PAN_ERR_OK
}

//////////
// Conn //
//////////

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
//export PanDialUDP
func PanDialUDP(
	local *C.cchar_t, remote C.PanUDPAddr,
	policy C.PanPolicy,
	selector C.PanSelector,
	conn *C.PanConn) C.PanError {
	var loc netaddr.IPPort = netaddr.IPPort{}
	var pol pan.Policy = nil
	var sel pan.Selector = nil
	var err error

	if local != nil {
		loc, err = netaddr.ParseIPPort(C.GoString(local))
		if err != nil {
			return C.PAN_ERR_ADDR_SYNTAX
		}
	}
	rem := cgo.Handle(remote).Value().(pan.UDPAddr)
	if policy != 0 {
		pol = cgo.Handle(policy).Value().(pan.Policy)
	}
	if selector != 0 {
		sel = cgo.Handle(selector).Value().(pan.Selector)
	}
	c, err := pan.DialUDP(context.Background(), loc, rem, pol, sel)
	if err != nil {
		return C.PAN_ERR_FAILED
	}
	ptr := (*C.PanConn)(unsafe.Pointer(conn))
	*ptr = C.PanConn(cgo.NewHandle(c))
	return C.PAN_ERR_OK
}

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
//export PanConnRead
func PanConnRead(conn C.PanConn, buffer *C.void, len C.int, n *C.int) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	read, err := c.Read(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(read)
	}

	return C.PAN_ERR_OK
}

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
//export PanConnReadVia
func PanConnReadVia(
	conn C.PanConn, buffer *C.void, len C.int, path *C.PanPath, n *C.int) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	read, via, err := c.ReadVia(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if path != nil {
		*(*C.PanPath)(unsafe.Pointer(path)) = C.PanPath(cgo.NewHandle(via))
	}
	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(read)
	}

	return C.PAN_ERR_OK
}

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
//export PanConnWrite
func PanConnWrite(conn C.PanListenConn, buffer *C.cvoid_t, len C.int, n *C.int) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)

	written, err := c.Write(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else if errors.Is(err, pan.ErrNoPath) {
			return C.PAN_ERR_NO_PATH
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(written)
	}

	return C.PAN_ERR_OK
}

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
//export PanConnWriteVia
func PanConnWriteVia(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int, path C.PanPath, n *C.int) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	via := cgo.Handle(path).Value().(*pan.Path)

	written, err := c.WriteVia(via, p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return C.PAN_ERR_DEADLINE
		} else {
			return C.PAN_ERR_FAILED
		}
	}

	if n != nil {
		*(*C.int)(unsafe.Pointer(n)) = C.int(written)
	}

	return C.PAN_ERR_OK
}

/**
\brief Wrapper for (pan.Conn).LocalAddr
\ingroup conn
*/
//export PanConnLocalAddr
func PanConnLocalAddr(conn C.PanConn) C.PanUDPAddr {
	c := cgo.Handle(conn).Value().(pan.Conn)
	return C.PanUDPAddr(cgo.NewHandle(c.LocalAddr()))
}

/**
\brief Wrapper for `(pan.Conn).RemoteAddr`
\ingroup conn
*/
//export PanConnRemoteAddr
func PanConnRemoteAddr(conn C.PanConn) C.PanUDPAddr {
	c := cgo.Handle(conn).Value().(pan.Conn)
	return C.PanUDPAddr(cgo.NewHandle(c.RemoteAddr()))
}

/**
\brief Wrapper for `(pan.Conn).SetDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
//export PanConnSetDeadline
func PanConnSetDeadline(conn C.PanConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	c.SetDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.Conn).SetReadDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
//export PanConnSetReadDeadline
func PanConnSetReadDeadline(conn C.PanConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	c.SetReadDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.Conn).SetWriteDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup conn
*/
//export PanConnSetWriteDeadline
func PanConnSetWriteDeadline(conn C.PanConn, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	c.SetWriteDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Close a connection. The handle must still be deleted with
PanDeleteHandle().
\ingroup conn
*/
//export PanConnClose
func PanConnClose(conn C.PanConn) C.PanError {
	handle := cgo.Handle(conn)
	err := handle.Value().(pan.Conn).Close()
	if err != nil {
		return C.PAN_ERR_FAILED
	}
	return C.PAN_ERR_OK
}

///////////////////////
// ListenSockAdapter //
///////////////////////

type ListenSockAdapter struct {
	pan_conn    pan.ListenConn
	unix_conn   *net.UnixConn
	unix_remote *net.UnixAddr
	listen_addr string
}

func NewListenSockAdapter(
	pan_conn pan.ListenConn, listen_addr string, client_addr string) (*ListenSockAdapter, error) {

	listen, err := net.ResolveUnixAddr("unixgram", listen_addr)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUnixAddr("unixgram", client_addr)
	if err != nil {
		return nil, err
	}

	os.Remove(listen_addr)
	unix_conn, err := net.ListenUnixgram("unixgram", listen)
	if err != nil {
		return nil, err
	}

	adapter := &ListenSockAdapter{
		pan_conn:    pan_conn,
		unix_conn:   unix_conn,
		unix_remote: remote,
		listen_addr: listen_addr,
	}

	go adapter.panToUnix()
	go adapter.unixToPan()

	return adapter, nil
}

func (ls *ListenSockAdapter) Close() error {
	ls.pan_conn.Close()
	ls.unix_conn.Close()
	os.Remove(ls.listen_addr)
	return nil
}

func (ls *ListenSockAdapter) panToUnix() {
	var buffer = make([]byte, 4096)
	for {
		// Read from network
		read, from, err := ls.pan_conn.ReadFrom(buffer[ADDR_HDR_SIZE:])
		if err != nil {
			return
		}

		// Prepend from header to received bytes
		pan_from, ok := from.(pan.UDPAddr)
		if !ok {
			continue
		}
		binary.BigEndian.PutUint64(buffer, (uint64)(pan_from.IA))
		if pan_from.IP.Is4() {
			buffer[8] = 4
			for i, b := range pan_from.IP.As4() {
				buffer[12+i] = b
			}
		} else {
			buffer[8] = 16
			for i, b := range pan_from.IP.As16() {
				buffer[12+i] = b
			}
		}
		binary.LittleEndian.PutUint16(buffer[28:30], pan_from.Port)
		message := buffer[:ADDR_HDR_SIZE+read]

		// Pass to unix socket
		_, err = ls.unix_conn.WriteToUnix(message, ls.unix_remote)
		if err != nil {
			return
		}
	}
}

func (ls *ListenSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from unix socket
		read, _, err := ls.unix_conn.ReadFromUnix(buffer)
		if err != nil {
			return
		}
		if read < ADDR_HDR_SIZE {
			continue
		}

		// Parse destination from header
		var to pan.UDPAddr
		to.IA = (pan.IA)(binary.BigEndian.Uint64(buffer[:8]))
		addr_len := binary.LittleEndian.Uint32(buffer[8:12])
		if addr_len == 4 {
			to.IP = netaddr.IPFrom4(*(*[4]byte)(buffer[12:16]))
		} else if addr_len == 16 {
			to.IP = netaddr.IPFrom16(*(*[16]byte)(buffer[12:28]))
		} else {
			continue
		}
		to.Port = binary.LittleEndian.Uint16(buffer[28:30])

		// Pass to network socket
		_, err = ls.pan_conn.WriteTo(buffer[ADDR_HDR_SIZE:read], to)
		if err != nil {
			return
		}
	}
}

/**
\brief Open a Unix datagram domain socket at `listen_addr` as proxy for `pan_conn`.

All packets received by `pan_conn` are forwarded from `listen_addr` to `client_addr`.
All packets received from the domain socket are forwarded to `pan_conn`.
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
\param[in] listen_addr Local address of the domain socket in the file system.
\param[in] client_addr Address of the other end of the connection in the C part
	of the program.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
//export PanNewListenSockAdapter
func PanNewListenSockAdapter(
	pan_conn C.PanListenConn, listen_addr *C.cchar_t, client_addr *C.cchar_t,
	adapter *C.PanListenSockAdapter) C.PanError {

	ls, err := NewListenSockAdapter(
		cgo.Handle(pan_conn).Value().(pan.ListenConn),
		C.GoString(listen_addr),
		C.GoString(client_addr))
	if err != nil {
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanListenSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the unix socket **and the PAN connection**.
\ingroup adapter
*/
//export PanListenSockAdapterClose
func PanListenSockAdapterClose(adapter C.PanListenSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ListenSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

/////////////////////
// ConnSockAdapter //
/////////////////////

type ConnSockAdapter struct {
	pan_conn    pan.Conn
	unix_conn   *net.UnixConn
	unix_remote *net.UnixAddr
	listen_addr string
}

func NewConnSockAdapter(
	pan_conn pan.Conn, listen_addr string, client_addr string) (*ConnSockAdapter, error) {

	listen, err := net.ResolveUnixAddr("unixgram", listen_addr)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUnixAddr("unixgram", client_addr)
	if err != nil {
		return nil, err
	}

	os.Remove(listen_addr)
	unix_conn, err := net.ListenUnixgram("unixgram", listen)
	if err != nil {
		return nil, err
	}

	adapter := &ConnSockAdapter{
		pan_conn:    pan_conn,
		unix_conn:   unix_conn,
		unix_remote: remote,
		listen_addr: listen_addr,
	}

	go adapter.panToUnix()
	go adapter.unixToPan()

	return adapter, nil
}

func (cs *ConnSockAdapter) Close() error {
	cs.pan_conn.Close()
	cs.unix_conn.Close()
	os.Remove(cs.listen_addr)
	return nil
}

func (cs *ConnSockAdapter) panToUnix() {
	var buffer = make([]byte, 4096)
	for {
		// Read from network
		read, err := cs.pan_conn.Read(buffer)
		if err != nil {
			return
		}

		// Pass to domain socket
		_, err = cs.unix_conn.WriteToUnix(buffer[:read], cs.unix_remote)
		if err != nil {
			return
		}
	}
}

func (cs *ConnSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from domain socket
		read, _, err := cs.unix_conn.ReadFromUnix(buffer)
		if err != nil {
			return
		}

		// Pass to network socket
		_, err = cs.pan_conn.Write(buffer[:read])
		if err != nil {
			return
		}
	}
}

/**
\brief Open a Unix datagram domain socket at `listen_addr` as proxy for `pan_conn`.

All packets received by pan_conn are forwarded from `listen_addr` to `client_addr`.
All packets received from the unix socket are forwarded to `pan_conn`.

\param[in] pan_conn Connected PAN connection.
\param[in] listen_addr Local address of the unix socket in the file system.
\param[in] client_addr Address of the other end of the connection in the C part
	of the program.
\param[out] adapter Socket adapter object.
\ingroup adapter
*/
//export PanNewConnSockAdapter
func PanNewConnSockAdapter(
	pan_conn C.PanConn, listen_addr *C.cchar_t, client_addr *C.cchar_t,
	adapter *C.PanConnSockAdapter) C.PanError {

	ls, err := NewConnSockAdapter(
		cgo.Handle(pan_conn).Value().(pan.Conn),
		C.GoString(listen_addr),
		C.GoString(client_addr))
	if err != nil {
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanConnSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the unix socket **and the PAN connection**.
\ingroup adapter
*/
//export PanConnSockAdapterClose
func PanConnSockAdapterClose(adapter C.PanConnSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ConnSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

//////////
// main //
//////////

func main() {
}
