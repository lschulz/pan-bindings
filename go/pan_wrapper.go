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
// #ifdef BINDGEN
// #include "pan_cdefs.h"
// #else
// #include "pan/pan_cdefs.h"
// #endif
// #define PAN_STREAM_HDR_SIZE 4
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
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"

	// "github.com/scionproto/scion/pkg/private/serrors"
	// "github.com/stretchr/testify/assert"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	// "github.com/scionproto/scion/private/app/flag"
	// "github.com/scionproto/scion/private/app/flag"

	// "github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	//"github.com/scionproto/scion/go/pkg/app"
	//	"github.com/scionproto/scion/go/pkg/app/flag"
	//"github.com/scionproto/scion/pkg/daemon"
	// "github.com/scionproto/scion/private/app"
)

const STREAM_HDR_SIZE = 4
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
\attention deprecated in favour of PanResolveUDPAddrN
		Reason:	conversion of C to Go string with func C.GoString(p *_Ctype_char) string
		has been repeatedly found to be unreliable and cause bugs.
\ingroup addresses
*/
//export PanResolveUDPAddr
func PanResolveUDPAddr(address *C.cchar_t, resolved *C.PanUDPAddr) C.PanError {
	var add = C.GoString(address)
	addr, err := pan.ResolveUDPAddr(context.Background(), add)
	if err != nil {

		if _, ok := err.(pan.HostNotFoundError); ok {
			return C.PAN_ERR_HOSTNOTFOUND
		}
		return C.PAN_ERR_ADDR_RESOLUTION
	}
	ptr := (*C.PanUDPAddr)(unsafe.Pointer(resolved))
	*ptr = C.PanUDPAddr(cgo.NewHandle(addr))
	return C.PAN_ERR_OK
}

//export PanResolveUDPAddrN
func PanResolveUDPAddrN(address *C.cchar_t, len C.int, resolved *C.PanUDPAddr) C.PanError {
	var add = C.GoBytes(unsafe.Pointer(address), len)
	addr, err := pan.ResolveUDPAddr(context.Background(), string(add))
	if err != nil {

		if _, ok := err.(pan.HostNotFoundError); ok {
			return C.PAN_ERR_HOSTNOTFOUND
		}
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
		addr.IP = netip.AddrFrom4(*b)
	} else if ip_len == 16 {
		b := (*[16]byte)(unsafe.Pointer(ip))
		addr.IP = netip.AddrFrom16(*b)
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
		if !address.IP.Is4() && !address.IP.Is4In6() {
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
		for _, path := range path_handles[0:newCount] {
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

//export PanCPolicyTest
func PanCPolicyTest(policy C.PanPolicy) {
	var pol pan.Policy

	if policy != 0 {
		pol = cgo.Handle(policy).Value().(pan.Policy)
	}

	var test_paths []*pan.Path = TestPaths()

	filtered_paths := pol.Filter(test_paths)

	fmt.Printf("len filtered_paths: %v\n", len(filtered_paths))

}

func TestPaths() []*pan.Path {
	unknown := time.Duration(0)

	asA := pan.MustParseIA("1-0:0:1")
	asB := pan.MustParseIA("1-0:0:2")
	asC := pan.MustParseIA("1-0:0:3")

	ifA1 := pan.PathInterface{IA: asA, IfID: 1}
	ifB1 := pan.PathInterface{IA: asB, IfID: 1}
	ifB2 := pan.PathInterface{IA: asB, IfID: 2}
	ifC2 := pan.PathInterface{IA: asC, IfID: 2}
	ifA3 := pan.PathInterface{IA: asA, IfID: 3}
	ifC3 := pan.PathInterface{IA: asC, IfID: 3}
	ifB4 := pan.PathInterface{IA: asB, IfID: 4}
	ifC4 := pan.PathInterface{IA: asC, IfID: 4}

	ifseqAC := []pan.PathInterface{ifA3, ifC3}
	//ifseqAB := []pan.PathInterface{ifA1, ifB2}
	ifseqABC := []pan.PathInterface{ifA1, ifB1, ifB2, ifC2}
	ifseqAB4C := []pan.PathInterface{ifA1, ifB1, ifB4, ifC4}

	var paths []*pan.Path = []*pan.Path{

		/*
			&pan.Path{
				Source       :  ,
				Destination  :  ,
				//ForwardingPath ForwardingPath
				Metadata       *PathMetadata // optional
				// Fingerprint    PathFingerprint
				// Expiry         time.Time
			},
		*/

		&pan.Path{
			Source:      asA,
			Destination: asC,
			//ForwardingPath ForwardingPath
			Metadata: &pan.PathMetadata{
				Interfaces: ifseqAC,
				Latency:    []time.Duration{1},
				MTU:        2304,
			},

			// Fingerprint    PathFingerprint
			// Expiry         time.Time
		},

		&pan.Path{
			Source:      asA,
			Destination: asC,
			//ForwardingPath ForwardingPath
			Metadata: &pan.PathMetadata{
				Interfaces: ifseqABC,
				Latency:    []time.Duration{1, 1, 1},
				MTU:        1500,
			},
			// Fingerprint    PathFingerprint
			// Expiry         time.Time
		},

		&pan.Path{
			Source:      asA,
			Destination: asC,
			//ForwardingPath ForwardingPath
			Metadata: &pan.PathMetadata{
				Interfaces: ifseqAB4C,
				Latency:    []time.Duration{unknown, 1, 2},
				MTU:        1500,
			},
			// Fingerprint    PathFingerprint
			// Expiry         time.Time
		},
	}
	return paths
}

//////////////
// Selector //
//////////////

type CSelector struct {
	local_ia  pan.IA
	callbacks C.struct_PanSelectorCallbacks
	user_data C.uintptr_t
}

func NewCSelector(callbacks *C.struct_PanSelectorCallbacks, user C.uintptr_t) *CSelector {
	return &CSelector{
		callbacks: *callbacks,
		user_data: user,
	}
}

func (s *CSelector) NewRemote(remote pan.UDPAddr) error {
	return nil
}

func (s *CSelector) GetIA() pan.IA {
	return s.local_ia
}

func (s *CSelector) Path(remote pan.UDPAddr) (*pan.Path, error) {
	path := C.panCallSelectorPath(s.callbacks.path, s.user_data)
	return cgo.Handle(path).Value().(*pan.Path), nil
}

func (s *CSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.local_ia = local.IA
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

func (s *CReplySelector) Path(remote pan.UDPAddr) (*pan.Path, error) {
	rem := cgo.NewHandle(remote)
	path := C.panCallReplySelPath(s.callbacks.path, C.PanUDPAddr(rem), s.user_data)
	return cgo.Handle(path).Value().(*pan.Path), nil
}

/*func (s *CReplySelector) Initialize(local pan.UDPAddr) {
	loc := cgo.NewHandle(local)
	C.panCallReplySelInitialize(s.callbacks.initialize, C.PanUDPAddr(loc), s.user_data)
} */

func (s *CReplySelector) Initialize(local pan.IA) {
	C.panCallReplySelInitialize(s.callbacks.initialize, C.cuint64_t(local), s.user_data)
}

func (s *CReplySelector) LocalAddrChanged(pan.UDPAddr) {

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

/* this combines pan.ListenConn and pan.ScionSocket so that they can share a common implementation
 */
type SocketLike interface {
	ReadFromVia(b []byte) (int, pan.UDPAddr, *pan.Path, error)
	WriteToVia(b []byte, dst pan.UDPAddr, path *pan.Path) (int, error)
	WriteTo(p []byte, addr net.Addr) (n int, err error)
	ReadFrom(p []byte) (n int, addr net.Addr, err error)
	SetReadDeadline(t time.Time) error
	Close() error
}

//////////////////////////////////////////////
///// SCION SOCKET
////////////////////////////////////////////////

/*

//export PanNewScionSocket
func PanNewScionSocket(listen *C.cchar_t, socket *C.PanScionSocket) C.PanError {
	local, err := netip.ParseAddrPort(C.GoString(listen))
	if err != nil {
		return C.PAN_ERR_ADDR_SYNTAX
	}
	sock, err := pan.NewScionSocket(context.Background(), local)
	if err != nil {
		return C.PAN_ERR_FAILED
	}
	ptr := (*C.PanScionSocket)(unsafe.Pointer(socket))
	p := C.PanScionSocket(cgo.NewHandle(sock))
	*ptr = p
	return C.PAN_ERR_OK
}

//export PanNewScionSocket2
func PanNewScionSocket2(socket *C.PanScionSocket) C.PanError {

	sock, err := pan.NewScionSocket2()
	if err != nil {
		return C.PAN_ERR_FAILED
	}
	ptr := (*C.PanScionSocket)(unsafe.Pointer(socket))
	p := C.PanScionSocket(cgo.NewHandle(sock))
	*ptr = p
	return C.PAN_ERR_OK
}
*/

//export PanNewScionSocket
func PanNewScionSocket(listen *C.cchar_t, n C.int) C.PanScionSocket {

	addr := string(C.GoBytes(unsafe.Pointer(listen), n))
	local, err := netip.ParseAddrPort(addr)
	if err != nil {
		l, e := pan.ParseUDPAddr(addr)
		if e != nil {
			panic(fmt.Sprintf("PanNewScionSocket error: %v", err))
		} else {
			local = netip.AddrPortFrom(l.IP, l.Port)
		}
	}
	sock, err := pan.NewScionSocket(context.Background(), local)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	if sock == nil {
		fmt.Println("PanNewScionSocket: socket was nil!")
	}

	p := C.PanScionSocket(cgo.NewHandle(sock))

	{
		mu00.Lock()
		cch := make(chan tuple00, 1)
		chann00s[uintptr(p)] = cch
		go fcn00(cch)
		mu00.Unlock()
	}
	{
		mu01.Lock()
		cch := make(chan tuple01, 1)
		chann01s[uintptr(p)] = cch
		go fcn01(cch)
		mu01.Unlock()
	}
	fmt.Println("pannewscionsocket returned successfully")
	return p
}

//export PanNewScionSocket2
func PanNewScionSocket2() C.PanScionSocket {
	sock, err := pan.NewScionSocket2()
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	p := C.PanScionSocket(cgo.NewHandle(sock))
	{
		mu00.Lock()
		cch := make(chan tuple00, 1)
		chann00s[uintptr(p)] = cch
		go fcn00(cch)
		mu00.Unlock()
	}
	{
		mu01.Lock()
		cch := make(chan tuple01, 1)
		chann01s[uintptr(p)] = cch
		go fcn01(cch)
		mu01.Unlock()
	}
	return p
}

//export PanScionSocketBind
func PanScionSocketBind(socket C.PanScionSocket, listen *C.cchar_t) C.PanError {
	s := cgo.Handle(socket).Value().(pan.ScionSocket)
	local := C.GoString(listen)
	addr, err := netip.ParseAddrPort(local)
	if err != nil {
		return C.PAN_ERR_ADDR_SYNTAX
	}

	if err = s.Bind(context.Background(), addr); err != nil {
		return C.PAN_ERR_FAILED
	}
	return C.PAN_ERR_OK

}

//export PanScionSocketGetLocalAddr
func PanScionSocketGetLocalAddr(socket C.PanScionSocket) *C.char {
	s := cgo.Handle(socket).Value().(pan.ScionSocket)

	return C.CString(s.LocalAddr().String())
}

func PanSocketLikeReadFromAsyncImpl(ch cgo.Handle, buffer *C.void, len C.int, from *C.PanUDPAddr, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	fmt.Println("PanSocketLikeReadFromAsyncImpl")
	c := ch.Value().(SocketLike)

	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	// Set read deadline to zero for non-blocking read
	if err := c.SetReadDeadline(time.Now()); err != nil {
		// fmt.Println("Error setting read deadline:", err)
		return C.PAN_ERR_FAILED
	}

	// Try to read
	read, add, err := c.ReadFrom(p)

	if err != nil {
		/*okk := reliable.IsDispatcherError(err)
		ook := errors.Is(err, io.EOF)
		fmt.Println("is_dispatcher_error: ", okk, " is EOF: ", ook)*/
		/*eerr := err
		for eerr != nil {
			fmt.Println(reflect.ValueOf(eerr).Type())
			eerr = errors.Unwrap(eerr)
		}*/

		/*
		   // IsTimeout returns whether err is or is caused by a timeout error.
		   func IsTimeout(err error) bool {
		   	var t interface{ Timeout() bool }
		   	return errors.As(err, &t) && t.Timeout()
		   }

		   // IsTemporary returns whether err is or is caused by a temporary error.
		   func IsTemporary(err error) bool
		*/

		var t interface{ Timeout() bool } // actually it is 'serrors.basicError' but i dont want to add scionproto as a dependency

		if errors.As(err, &t) {

			if t.Timeout() {
				// Read would block in non-blocking mode

				// Launch a goroutine for non-blocking read
				var chann01 chan tuple01
				{
					mu01.Lock()
					conn := C.PanScionSocket(ch)
					chann01 = chann01s[uintptr(conn)]
					mu01.Unlock()
				}
				chann01 <- tuple01{p, c, from, nil, n, waker, arc_conn}

				return C.PAN_ERR_WOULDBLOCK
				// return Pending
			} // if Timeout()
		} else {
			// fmt.Println("Error on initial read:", err)
			// return error  other than timeout
			return C.PAN_ERR_FAILED
		}
	} else {
		// Read successful
		// fmt.Printf("Read %d bytes: %s\n", n, buffer[:read])

		if add != nil {
			*(*C.PanUDPAddr)(unsafe.Pointer(from)) = C.PanUDPAddr(cgo.NewHandle(add))
		}
		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(read)
		}

		return C.PAN_ERR_OK

	}

	return C.PAN_ERR_OK
}

//export PanScionSocketReadFromAsync
func PanScionSocketReadFromAsync(conn C.PanScionSocket, buffer *C.void, len C.int, from *C.PanUDPAddr, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn)
	return PanSocketLikeReadFromAsyncImpl(c, buffer, len, from, n, timeout_duration, waker, arc_conn)
}

//export PanScionSocketWriteToAsync
func PanScionSocketWriteToAsync(
	conn C.PanScionSocket, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {

	c := cgo.Handle(conn)
	return PanSocketLikeWriteToAsyncImpl(c, buffer, len, to, n, timeout, waker, arc_conn)
}

//export PanScionSocketWriteToViaAsync
func PanScionSocketWriteToViaAsync(
	conn C.PanScionSocket, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, path C.PanPath, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {

	c := cgo.Handle(conn)
	return PanSocketLikeWriteToViaAsyncImpl(c, buffer, len, to, path, n, timeout, waker, arc_conn)
}

func PanSocketLikeReadFromAsyncViaImpl(ch cgo.Handle, buffer *C.void, len C.int, from *C.PanUDPAddr, path *C.PanPath, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {

	c := ch.Value().(SocketLike)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	// Set read deadline to zero for non-blocking read
	if err := c.SetReadDeadline(time.Now()); err != nil {
		// fmt.Println("Error setting read deadline:", err)
		return C.PAN_ERR_FAILED
	}

	// Try to read
	read, add, from_path, err := c.ReadFromVia(p)

	if err != nil {

		var t interface{ Timeout() bool } // actually it is 'serrors.basicError' but i dont want to add scionproto as a dependency

		if errors.As(err, &t) {

			if t.Timeout() {
				// Read would block in non-blocking mode
				var chann01 chan tuple01
				{
					mu01.Lock()
					conn := C.PanScionSocket(ch)
					chann01 = chann01s[uintptr(conn)]
					mu01.Unlock()
				}

				chann01 <- tuple01{p, c, from, path, n, waker, arc_conn}

				// Launch a goroutine for non-blocking read

				return C.PAN_ERR_WOULDBLOCK
				// return Pending
			} // if Timeout()
		} else {
			// fmt.Println("Error on initial read:", err)
			// return error  other than timeout
			return C.PAN_ERR_FAILED
		}
	} else {
		// Read successful
		// fmt.Printf("Read %d bytes: %s\n", n, buffer[:read])

		if from != nil {
			*(*C.PanUDPAddr)(unsafe.Pointer(from)) = C.PanUDPAddr(cgo.NewHandle(add))
		}
		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(read)
		}
		if path != nil {
			*(*C.PanPath)(unsafe.Pointer(path)) = C.PanPath(cgo.NewHandle(from_path))
		}

		return C.PAN_ERR_OK

	}

	panic("unreachable")
}

//export PanScionSocketReadFromAsyncVia
func PanScionSocketReadFromAsyncVia(conn C.PanScionSocket, buffer *C.void, len C.int, from *C.PanUDPAddr, path *C.PanPath, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn)
	return PanSocketLikeReadFromAsyncViaImpl(c, buffer, len, from, path, n, timeout_duration, waker, arc_conn)
}

//export PanScionSocketClose
func PanScionSocketClose(conn C.PanScionSocket) C.PanError {
	handle := cgo.Handle(conn)
	return SocketLikeCloseImpl(handle)
}

/**
\brief Wrapper for `(pan.ListenConn).SetDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
//export PanScionSocketSetDeadline
func PanScionSocketSetDeadline(conn C.PanScionSocket, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ScionSocket)
	c.SetDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
}

/**
\brief Wrapper for `(pan.ListenConn).SetReadDeadline`
\param[in] conn Connection to set the deadline on.
\param[in] t is the number milliseconds the deadline is set in the future.
\ingroup listen_conn
*/
//export PanScionSocketSetReadDeadline
func PanScionSocketSetReadDeadline(conn C.PanScionSocket, t C.uint32_t) C.PanError {
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
//export PanScionSocketSetWriteDeadline
func PanScionSocketSetWriteDeadline(conn C.PanScionSocket, t C.uint32_t) C.PanError {
	c := cgo.Handle(conn).Value().(pan.ListenConn)
	c.SetWriteDeadline(time.Now().Add(time.Duration(t) * time.Millisecond))
	return C.PAN_ERR_OK
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

	local, err := netip.ParseAddrPort(C.GoString(listen))
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
	p := C.PanListenConn(cgo.NewHandle(c))
	*ptr = p

	{
		mu00.Lock()
		cch := make(chan tuple00, 1)
		chann00s[uintptr(p)] = cch
		go fcn00(cch)
		mu00.Unlock()
	}
	{
		mu01.Lock()
		cch := make(chan tuple01, 1)
		chann01s[uintptr(p)] = cch
		go fcn01(cch)
		mu01.Unlock()
	}

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
//export PanListenConnReadFromAsync
func PanListenConnReadFromAsync(conn C.PanListenConn, buffer *C.void, len C.int, from *C.PanUDPAddr, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn)
	return PanSocketLikeReadFromAsyncImpl(c, buffer, len, from, n, timeout_duration, waker, arc_conn)
}

// ListenConn ReadFrom
type tuple01 struct {
	buffer_out       []byte
	conn             SocketLike          // or ptr-to ?!
	from_out         *C.PanUDPAddr       // *_Ctype_ulong
	path_out         *C.PanPath          // *_Ctype_ulong
	bytes_read_out   *C.int              // *_Ctype_int
	completion_waker C.OnCompletionWaker // _Ctype_OnCompletionWaker
	arc_conn         *C.void
	// timeout has to go here
}

var chann01 chan tuple01

func fcn01(chann01 chan tuple01) {

	for {
		recv_op := <-chann01

		buffer_out := recv_op.buffer_out
		conn := recv_op.conn
		from_out := recv_op.from_out
		path_out := recv_op.path_out
		bytes_read_out := recv_op.bytes_read_out
		completion_waker := recv_op.completion_waker
		arc_conn := recv_op.arc_conn

		//		if errr := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout_duration) * time.Millisecond)); errr != nil {
		if errr := conn.SetReadDeadline(time.Time{}); errr != nil {
			// fmt.Println("Error setting read deadline:", errr)
			// call waker with C.PAN_ERR_FAILED
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
			continue
		}

		var nn int
		var addr pan.UDPAddr
		var path_ *pan.Path
		var errrr error
		if path_out != nil {
			nn, addr, path_, errrr = conn.ReadFromVia(buffer_out) // block here for new data
		} else {
			n, a, e := conn.ReadFrom(buffer_out)
			nn, addr, errrr = n, a.(pan.UDPAddr), e
		}

		if errrr == nil {
			// Data is available, signal the main caller
			// read successfully completed out of band, invoking handler

			if from_out != nil {
				*(*C.PanUDPAddr)(unsafe.Pointer(from_out)) = C.PanUDPAddr(cgo.NewHandle(addr))
			}
			if bytes_read_out != nil {
				*(*C.int)(unsafe.Pointer(bytes_read_out)) = C.int(nn)
			}
			if path_out != nil {
				*(*C.PanPath)(unsafe.Pointer(path_out)) = C.PanPath(cgo.NewHandle(path_))
			}

			//  call waker with C.PAN_ERR_OK here
			// notify the rust future, that the result is now available
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_OK)
			continue

		} else {
			//fmt.Println("Error reading out of band: ", errrr)

			var tt interface{ Timeout() bool }
			if errors.As(errrr, &tt) {
				if tt.Timeout() {
					// call waker with C.PAN_ERR_DEADLINE here  -> the callback on the rust side must transition the state according to ret-code
					// and eventuall reschedule the rust future to be polled again
					C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_DEADLINE)
					continue
				}
			}

			// check if error is timeout and return the right error code
			// call waker with C.PAN_ERR_FAILED here
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
		}

	}
}

//export PanListenConnReadFromAsyncVia
func PanListenConnReadFromAsyncVia(conn C.PanListenConn, buffer *C.void, len C.int, from *C.PanUDPAddr, path *C.PanPath, n *C.int, timeout_duration C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn)
	return PanSocketLikeReadFromAsyncViaImpl(c, buffer, len, from, path, n, timeout_duration, waker, arc_conn)
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

func PanSocketLikeWriteToViaAsyncImpl(
	ch cgo.Handle, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, path C.PanPath, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := ch.Value().(SocketLike)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	addr := cgo.Handle(to).Value().(pan.UDPAddr)
	via := cgo.Handle(path).Value().(*pan.Path)

	// Set write deadline to zero for non-blocking write
	/*if err := c.SetWriteDeadline(time.Now()); err != nil {
		fmt.Println("Error setting write deadline:", err)
		return C.PAN_ERR_FAILED
	}

	written, err := c.WriteToVia(p, addr,via)
	*/
	//if err != nil {
	var err error
	var written = 0
	if true {

		//var t interface{ Timeout() bool }

		//if errors.As(err, &t) {
		if true {

			//if t.Timeout() {
			if true {
				// dispatch a non-blocking write operation and pass along the required parameters
				var chann00 chan tuple00
				{
					mu00.Lock()
					conn := C.PanScionSocket(ch)
					chann00 = chann00s[uintptr(conn)]
					mu00.Unlock()
				}

				chann00 <- tuple00{p, addr, via, n, waker, c, arc_conn}

				return C.PAN_ERR_WOULDBLOCK
			} else {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return C.PAN_ERR_DEADLINE
				} else if errors.Is(err, pan.ErrNoPath) {
					return C.PAN_ERR_NO_PATH
				} else {
					return C.PAN_ERR_FAILED
				}
			}

		} else {

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return C.PAN_ERR_DEADLINE
			} else if errors.Is(err, pan.ErrNoPath) {
				return C.PAN_ERR_NO_PATH
			} else {
				return C.PAN_ERR_FAILED
			}
		}

	} else { // write completed immediately

		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(written)
		}

		return C.PAN_ERR_OK
	}

	panic("unreachable")
}

func PanSocketLikeWriteToAsyncImpl(
	ch cgo.Handle, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := ch.Value().(SocketLike)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	addr := cgo.Handle(to).Value().(pan.UDPAddr)

	// Set write deadline to zero for non-blocking write
	/*if err := c.SetWriteDeadline(time.Now()); err != nil {
		fmt.Println("Error setting write deadline:", err)
		return C.PAN_ERR_FAILED
	}

	written, err := c.WriteTo(p, addr)
	*/
	//if err != nil {
	var err error
	var written = 0
	if true {

		//var t interface{ Timeout() bool }

		//if errors.As(err, &t) {
		if true {

			//if t.Timeout() {
			if true {

				var chann00 chan tuple00
				{
					mu00.Lock()
					conn := C.PanScionSocket(ch)
					chann00 = chann00s[uintptr(conn)]
					mu00.Unlock()
				}
				chann00 <- tuple00{p, addr, nil, n, waker, c, arc_conn}

				return C.PAN_ERR_WOULDBLOCK
			} else {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return C.PAN_ERR_DEADLINE
				} else if errors.Is(err, pan.ErrNoPath) {
					return C.PAN_ERR_NO_PATH
				} else {
					return C.PAN_ERR_FAILED
				}
			}

		} else {

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return C.PAN_ERR_DEADLINE
			} else if errors.Is(err, pan.ErrNoPath) {
				return C.PAN_ERR_NO_PATH
			} else {
				return C.PAN_ERR_FAILED
			}
		}

	} else { // write completed immediately

		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(written)
		}

		return C.PAN_ERR_OK
	}

	panic("unreachable")
}

//export PanListenConnWriteToAsync
func PanListenConnWriteToAsync(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {

	c := cgo.Handle(conn)
	return PanSocketLikeWriteToAsyncImpl(c, buffer, len, to, n, timeout, waker, arc_conn)
}

type tuple00 struct {
	send_buff []byte
	to_addr   pan.UDPAddr // or pointer-to ?!
	to_path   *pan.Path
	written   *C.int
	completer C.OnCompletionWaker
	conn      SocketLike // or pointer-to ?!
	arc_conn  *C.void
	// timeout also has to go here
}

func fcn00(chann00 chan tuple00) {

	for {

		// receive parameters for a write-operation
		recv_operation := <-chann00

		send_buff := recv_operation.send_buff
		to_addr := recv_operation.to_addr
		to_path := recv_operation.to_path
		written := recv_operation.written
		completer := recv_operation.completer
		conn := recv_operation.conn
		arc_conn := recv_operation.arc_conn

		// set write timeout to 'timeout' here
		/*	if errr := conn.SetWriteDeadline(time.Time{}); errr != nil {
				C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
				return
			}
		*/

		var out int = 0
		var e error
		if to_path != nil {
			out, e = conn.WriteToVia(send_buff, to_addr, to_path)
		} else {
			out, e = conn.WriteTo(send_buff, to_addr)
		}

		if e == nil { // write completed successfully out of band

			if written != nil {
				*(*C.int)(unsafe.Pointer(written)) = C.int(out)
			}
			C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_OK)
		} else {
			var tt interface{ Timeout() bool }
			if errors.As(e, &tt) {

				if tt.Timeout() { // async write timeout
					C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_DEADLINE)
					continue
				}
			}
			C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)

		}
	}
}

//export PanListenConnWriteToViaAsync
func PanListenConnWriteToViaAsync(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int, to C.PanUDPAddr, path C.PanPath, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {

	c := cgo.Handle(conn)
	return PanSocketLikeWriteToViaAsyncImpl(c, buffer, len, to, path, n, timeout, waker, arc_conn)
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
	return SocketLikeCloseImpl(handle)
}

func SocketLikeCloseImpl(handle cgo.Handle) C.PanError {
	conn := C.PanScionSocket(handle)
	err := handle.Value().(SocketLike).Close()
	{
		mu00.Lock()

		close(chann00s[uintptr(conn)])
		delete(chann00s, uintptr(conn))

		mu00.Unlock()
	}
	{
		mu01.Lock()

		close(chann01s[uintptr(conn)])
		delete(chann01s, uintptr(conn))
		mu01.Unlock()
	}

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
	var loc netip.AddrPort = netip.AddrPort{}
	var pol pan.Policy = nil
	var sel pan.Selector = nil
	var err error

	if local != nil {
		loc, err = netip.ParseAddrPort(C.GoString(local))
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
	p := C.PanConn(cgo.NewHandle(c))
	*ptr = p
	{
		mu02.Lock()
		cch := make(chan tuple02, 1)
		chann02s[uintptr(p)] = cch
		go fcn02(cch)
		mu02.Unlock()
	}
	{
		mu03.Lock()
		cch := make(chan tuple03, 1)
		chann03s[uintptr(p)] = cch
		go fcn03(cch)
		mu03.Unlock()
	}

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

// pan.Conn readVia
type tuple02 struct {
	buffer_out       []byte
	conn             pan.Conn // or ptr-to ?!
	path_out         *C.PanPath
	bytes_read_out   *C.int
	completion_waker C.OnCompletionWaker
	arc_conn         *C.void
	// add timeout here
}

func fcn02(chann02 chan tuple02) {

	for {

		recv_op := <-chann02
		buffer_out := recv_op.buffer_out
		conn := recv_op.conn
		path_out := recv_op.path_out
		bytes_read_out := recv_op.bytes_read_out
		completion_waker := recv_op.completion_waker
		arc_conn := recv_op.arc_conn

		//		if errr := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout_duration) * time.Millisecond)); errr != nil {
		if errr := conn.SetReadDeadline(time.Time{}); errr != nil {
			// fmt.Println("Error setting read deadline:", errr)
			// call waker with C.PAN_ERR_FAILED
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
			continue
		}

		var nn int
		var path_ *pan.Path
		var errrr error
		if path_out != nil {
			nn, path_, errrr = conn.ReadVia(buffer_out) // block here for new data
		} else {
			nn, errrr = conn.Read(buffer_out)
		}

		if errrr == nil {
			// Data is available, signal the main caller
			// read successfully completed out of band, invoking handler

			if bytes_read_out != nil {
				*(*C.int)(unsafe.Pointer(bytes_read_out)) = C.int(nn)
			}
			if path_ != nil {
				*(*C.PanPath)(unsafe.Pointer(path_out)) = C.PanPath(cgo.NewHandle(path_))
			}

			//  call waker with C.PAN_ERR_OK here
			// notify the rust future, that the result is now available
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_OK)
			continue

		} else {
			// Error reading out of band

			var tt interface{ Timeout() bool }
			if errors.As(errrr, &tt) {
				if tt.Timeout() {
					// call waker with C.PAN_ERR_DEADLINE here  -> the callback on the rust side must transition the state according to ret-code
					// and eventuall reschedule the rust future to be polled again
					C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_DEADLINE)
					continue
				}
			}

			// check if error is timeout and return the right error code
			// call waker with C.PAN_ERR_FAILED here
			C.InvokeCompletionWaker(completion_waker, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
		}
	}
}

//export PanConnReadViaAsync
func PanConnReadViaAsync(
	conn C.PanConn, buffer *C.void, len C.int, path *C.PanPath, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len)

	// Set read deadline to zero for non-blocking read
	if erer := c.SetReadDeadline(time.Now()); erer != nil {
		// fmt.Println("Error setting read deadline:", erer)
		return C.PAN_ERR_FAILED
	}

	// Try to read
	read, from_path, err := c.ReadVia(p)

	if err != nil {

		var t interface{ Timeout() bool } // actually it is 'serrors.basicError' but i dont want to add scionproto as a dependency

		if errors.As(err, &t) {
			if t.Timeout() {
				// Read would block in non-blocking mode
				var chann02 chan tuple02
				{
					mu02.Lock()
					chann02 = chann02s[uintptr(conn)]
					mu02.Unlock()
				}

				chann02 <- tuple02{p, c, path, n, waker, arc_conn}

				return C.PAN_ERR_WOULDBLOCK
				// return Pending
			} // if Timeout()
		} else {
			// Error on initial read
			// return error  other than timeout
			return C.PAN_ERR_FAILED
		}
	} else {
		// Read successful
		//fmt.Printf("Read %d bytes: %s\n", n, p[:read])

		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(read)
		}
		if path != nil {
			*(*C.PanPath)(unsafe.Pointer(path)) = C.PanPath(cgo.NewHandle(from_path))
		}

		return C.PAN_ERR_OK

	}

	panic("unreachable")

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

type tuple03 struct {
	send_buff []byte
	written   *C.int
	to_path   *pan.Path
	completer C.OnCompletionWaker
	conn      pan.Conn
	arc_conn  *C.void
}

func fcn03(chann03 chan tuple03) {
	for {

		recv_op := <-chann03

		send_buff := recv_op.send_buff
		written := recv_op.written
		to_path := recv_op.to_path
		completer := recv_op.completer
		conn := recv_op.conn
		arc_conn := recv_op.arc_conn

		// set write timeout to 'timeout' here
		/*	if errr := conn.SetWriteDeadline(time.Time{}); errr != nil {
				C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
				return
			}
		*/

		var out int = 0
		var e error

		if to_path == nil {
			out, e = conn.Write(send_buff)
		} else {
			out, e = conn.WriteVia(to_path, send_buff)
		}

		if e == nil {
			// write successfully completed out of band
			if written != nil {
				*(*C.int)(unsafe.Pointer(written)) = C.int(out)
			}
			C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_OK)
		} else {
			var tt interface{ Timeout() bool }
			if errors.As(e, &tt) {

				if tt.Timeout() {
					// async write timeout
					C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_DEADLINE)
					continue
				}
			}
			C.InvokeCompletionWaker(completer, unsafe.Pointer(arc_conn), C.PAN_ERR_FAILED)
			continue
		}

	}
}

//export PanConnWriteAsync
func PanConnWriteAsync(conn C.PanListenConn, buffer *C.cvoid_t, len C.int, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)

	// Set write deadline to zero for non-blocking write
	/*if err := c.SetWriteDeadline(time.Now()); err != nil {
		fmt.Println("Error setting write deadline:", err)
		return C.PAN_ERR_FAILED
	}

	written, err := c.WriteTo(p, addr)
	*/
	//if err != nil {
	var err error
	var written = 0
	if true {

		//var t interface{ Timeout() bool }

		//if errors.As(err, &t) {
		if true {

			//if t.Timeout() {
			if true { // write would block
				var chann03 chan tuple03
				{
					mu03.Lock()
					chann03 = chann03s[uintptr(conn)]
					mu03.Unlock()
				}

				chann03 <- tuple03{p, n, nil, waker, c, arc_conn}
				// launch a go routine for non-blocking write

				return C.PAN_ERR_WOULDBLOCK
			} else {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return C.PAN_ERR_DEADLINE
				} else if errors.Is(err, pan.ErrNoPath) {
					return C.PAN_ERR_NO_PATH
				} else {
					return C.PAN_ERR_FAILED
				}
			}

		} else {

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return C.PAN_ERR_DEADLINE
			} else if errors.Is(err, pan.ErrNoPath) {
				return C.PAN_ERR_NO_PATH
			} else {
				return C.PAN_ERR_FAILED
			}
		}

	} else { // write completed immediately

		// write completed immediately
		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(written)
		}

		return C.PAN_ERR_OK
	}

	panic("unreachable")
}

var envFlags flag.SCIONEnvironment
var service daemon.Service
var mu00 sync.Mutex
var mu01 sync.Mutex
var mu02 sync.Mutex
var mu03 sync.Mutex
var chann00s map[uintptr]chan tuple00
var chann01s map[uintptr]chan tuple01
var chann02s map[uintptr]chan tuple02
var chann03s map[uintptr]chan tuple03

func init() {
	fmt.Println("INIT CALLED")

	if err := envFlags.LoadExternalVars(); err != nil {
		panic(fmt.Sprintf("pan initialization failed: %v", err))
	}
	daemonAddr := envFlags.Daemon()

	service = daemon.NewService(daemonAddr)

	chann00s = make(map[uintptr]chan tuple00)
	chann01s = make(map[uintptr]chan tuple01)
	chann02s = make(map[uintptr]chan tuple02)
	chann03s = make(map[uintptr]chan tuple03)

}

//export GetLocalIA
func GetLocalIA() uint64 {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	conn, err := service.Connect(ctx)
	if err != nil {
		panic(fmt.Sprintf("connecting to SCION Daemon: %v", err))
	}
	defer conn.Close()

	info, err := app.QueryASInfo(ctx, conn)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	return uint64(info.IA)

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

//export PanConnWriteViaAsync
func PanConnWriteViaAsync(
	conn C.PanListenConn, buffer *C.cvoid_t, len C.int, path C.PanPath, n *C.int, timeout C.int, waker C.OnCompletionWaker, arc_conn *C.void) C.PanError {
	c := cgo.Handle(conn).Value().(pan.Conn)
	p := C.GoBytes(unsafe.Pointer(buffer), len)
	via := cgo.Handle(path).Value().(*pan.Path)

	// Set write deadline to zero for non-blocking write
	/*if err := c.SetWriteDeadline(time.Now()); err != nil {
		fmt.Println("Error setting write deadline:", err)
		return C.PAN_ERR_FAILED
	}

	written, err := c.WriteVia(via,p)
	*/
	//if err != nil {
	var err error
	var written = 0
	if true {

		//var t interface{ Timeout() bool }

		//if errors.As(err, &t) {
		if true {

			//if t.Timeout() {
			if true {

				// write would block
				var chann03 chan tuple03
				{
					mu03.Lock()
					chann03 = chann03s[uintptr(conn)]
					mu03.Unlock()
				}
				chann03 <- tuple03{p, n, via, waker, c, arc_conn}

				return C.PAN_ERR_WOULDBLOCK
			} else {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return C.PAN_ERR_DEADLINE
				} else if errors.Is(err, pan.ErrNoPath) {
					return C.PAN_ERR_NO_PATH
				} else {
					return C.PAN_ERR_FAILED
				}
			}

		} else {

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return C.PAN_ERR_DEADLINE
			} else if errors.Is(err, pan.ErrNoPath) {
				return C.PAN_ERR_NO_PATH
			} else {
				return C.PAN_ERR_FAILED
			}
		}

	} else { // write completed immediately

		// write completed immediately
		if n != nil {
			*(*C.int)(unsafe.Pointer(n)) = C.int(written)
		}

		return C.PAN_ERR_OK
	}

	panic("unreachable")
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
	{
		mu02.Lock()

		close(chann02s[uintptr(conn)])
		delete(chann02s, uintptr(conn))

		mu02.Unlock()
	}
	{
		mu03.Lock()

		close(chann03s[uintptr(conn)])
		delete(chann03s, uintptr(conn))
		mu03.Unlock()
	}

	if err != nil {
		return C.PAN_ERR_FAILED
	}
	return C.PAN_ERR_OK
}

///////////////////////
// ListenSockAdapter //
///////////////////////

/**
\brief Open a Unix datagram socket at `listen_addr` as proxy for `pan_conn` or scion_socket (any SocketLike type).
\attention deprecated in favour of PanNewListenSockAdapter2
		Reason:	conversion of C to Go string with func C.GoString(p *_Ctype_char) string has been repeatedly found to be unreliable and cause bugs.
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

\param[in] pan_conn Listening PAN connection or ScionSocket (any type that implements SocketLike).
\param[in] listen_addr Local address of the socket in the file system.
			On the 'FFI caller' side a unix domain socket must have been constructed an bound to this address
			before the adapter is constructed.
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
		cgo.Handle(pan_conn).Value().(SocketLike),
		C.GoString(listen_addr),
		C.GoString(client_addr))
	if err != nil {
		fmt.Println("PanNewListenSockAdapter failed")
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanListenSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

//export PanNewListenSockAdapter2
func PanNewListenSockAdapter2(
	pan_conn C.PanListenConn, listen_addr *C.cchar_t, len1 C.int, client_addr *C.cchar_t, len2 C.int,
	adapter *C.PanListenSockAdapter) C.PanError {

	var listen = C.GoBytes(unsafe.Pointer(listen_addr), len1)
	var client = C.GoBytes(unsafe.Pointer(client_addr), len2)

	ls, err := NewListenSockAdapter(
		cgo.Handle(pan_conn).Value().(SocketLike),
		string(listen),
		string(client))
	if err != nil {
		fmt.Println("PanNewListenSockAdapter failed")
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanListenSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
//export PanListenSockAdapterClose
func PanListenSockAdapterClose(adapter C.PanListenSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ListenSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

type ListenSockAdapter struct {
	pan_conn    SocketLike
	unix_conn   *net.UnixConn
	unix_remote *net.UnixAddr
	listen_addr string
}

func NewListenSockAdapter(
	pan_conn SocketLike, listen_addr string, client_addr string) (*ListenSockAdapter, error) {

	listen, err := net.ResolveUnixAddr("unixgram", listen_addr)
	if err != nil {
		fmt.Printf("NewListenSockAdapter failed to resolv listen: %v\n", err)
		return nil, err
	}
	remote, err := net.ResolveUnixAddr("unixgram", client_addr)
	if err != nil {
		fmt.Printf("NewListenSockAdapter failed to resolv client: %v\n", err)
		return nil, err
	}

	os.Remove(listen_addr)
	unix_conn, err := net.ListenUnixgram("unixgram", listen)
	if err != nil {
		fmt.Printf("NewListenSockAdapter failed to listen: %v\n", err)
		return nil, err
	}

	adapter := &ListenSockAdapter{
		pan_conn:    pan_conn,
		unix_conn:   unix_conn,
		unix_remote: remote,
		listen_addr: listen_addr,
	}
	fmt.Printf("%v -> %v\n", listen_addr, client_addr)
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
		fmt.Printf("read %v bytes from pan \n", read)
		if err != nil {
			fmt.Printf("failed to read from pan: %v\n", err)
			return
		}

		// Prepend from header to received bytes
		pan_from, ok := from.(pan.UDPAddr)
		if !ok {
			// 	continue
			panic("logic error")
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

		var n int = 0
		// Pass to unix socket
		n, err = ls.unix_conn.WriteToUnix(message, ls.unix_remote)
		fmt.Printf("wrote %v bytes to unix ", n)
		if err != nil {
			fmt.Printf("failed to write to unix: %v", err)
			return
		}
	}
}

func (ls *ListenSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from unix socket
		read, _, err := ls.unix_conn.ReadFromUnix(buffer)
		fmt.Printf("read %v byte from unix\n", read)
		if err != nil {
			fmt.Printf("failed to read from unix: %v\n", err)
			return
		}
		if read < ADDR_HDR_SIZE {
			fmt.Println("WARNING: received less than proxy header from unix")
			continue
		}

		// Parse destination from header
		var to pan.UDPAddr
		to.IA = (pan.IA)(binary.BigEndian.Uint64(buffer[:8]))
		addr_len := binary.LittleEndian.Uint32(buffer[8:12])
		if addr_len == 4 {
			to.IP = netip.AddrFrom4(*(*[4]byte)(buffer[12:16]))
		} else if addr_len == 16 {
			to.IP = netip.AddrFrom16(*(*[16]byte)(buffer[12:28]))
		} else {
			fmt.Println("WARNING: invalid proxy header read from unix")
			continue
		}
		to.Port = binary.LittleEndian.Uint16(buffer[28:30])

		// Pass to network socket
		var n int
		n, err = ls.pan_conn.WriteTo(buffer[ADDR_HDR_SIZE:read], to)
		fmt.Printf("wrote %v byte to pan ->%v\n", n, to.String())
		if err != nil {
			fmt.Printf("failed to write to pan: %v\n", err)
			return
		}
	}
}

/////////////////////
// ConnSockAdapter //
/////////////////////

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

	ptr := (*C.PanConnSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanConnSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
//export PanConnSockAdapterClose
func PanConnSockAdapterClose(adapter C.PanConnSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ConnSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

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

		// Pass to Unix domain socket
		_, err = cs.unix_conn.WriteToUnix(buffer[:read], cs.unix_remote)
		if err != nil {
			return
		}
	}
}

func (cs *ConnSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from Unix domain socket
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

////////////////////////
// ListenSSockAdapter //
////////////////////////

/**
\brief Open a Unix stream socket at `listen_addr` as proxy for `pan_conn` or 'scion_socket'(any SocketLike).

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
//export PanNewListenSSockAdapter
func PanNewListenSSockAdapter(
	pan_conn C.PanListenConn, listen_addr *C.cchar_t,
	adapter *C.PanListenSSockAdapter) C.PanError {

	ls, err := NewListenSSockAdapter(
		cgo.Handle(pan_conn).Value().(pan.ListenConn),
		C.GoString(listen_addr))
	if err != nil {
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanListenSSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanListenSSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
//export PanListenSSockAdapterClose
func PanListenSSockAdapterClose(adapter C.PanListenSSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ListenSSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

type ListenSSockAdapter struct {
	pan_conn      SocketLike
	unix_listener *net.UnixListener
	unix_conn     *net.UnixConn
}

func NewListenSSockAdapter(
	pan_conn SocketLike, listen_addr string) (*ListenSSockAdapter, error) {

	listen, err := net.ResolveUnixAddr("unix", listen_addr)
	if err != nil {
		return nil, err
	}

	os.Remove(listen_addr)
	unix_listener, err := net.ListenUnix("unix", listen)
	if err != nil {
		return nil, err
	}
	unix_listener.SetUnlinkOnClose(true)

	adapter := &ListenSSockAdapter{
		pan_conn:      pan_conn,
		unix_listener: unix_listener,
		unix_conn:     nil,
	}

	go adapter.waitForConn()

	return adapter, nil
}

func (ls *ListenSSockAdapter) waitForConn() {
	conn, err := ls.unix_listener.AcceptUnix()
	defer ls.unix_listener.Close()
	if err != nil {
		return
	}
	ls.unix_conn = conn
	go ls.panToUnix()
	go ls.unixToPan()
}

func (ls *ListenSSockAdapter) Close() error {
	ls.pan_conn.Close()
	ls.unix_conn.Close()
	return nil
}

func (ls *ListenSSockAdapter) panToUnix() {
	var buffer = make([]byte, 4096)
	for {
		// Read from network
		read, from, err := ls.pan_conn.ReadFrom(buffer[STREAM_HDR_SIZE+ADDR_HDR_SIZE:])
		if err != nil {
			return
		}

		// Prepend message length
		binary.LittleEndian.PutUint32(buffer[0:4], uint32(read+ADDR_HDR_SIZE))

		// Prepend from header to received bytes
		pan_from, ok := from.(pan.UDPAddr)
		if !ok {
			continue
		}
		binary.BigEndian.PutUint64(buffer[4:12], (uint64)(pan_from.IA))
		if pan_from.IP.Is4() {
			buffer[12] = 4
			for i, b := range pan_from.IP.As4() {
				buffer[16+i] = b
			}
		} else {
			buffer[12] = 16
			for i, b := range pan_from.IP.As16() {
				buffer[16+i] = b
			}
		}
		binary.LittleEndian.PutUint16(buffer[32:34], pan_from.Port)
		message := buffer[:STREAM_HDR_SIZE+ADDR_HDR_SIZE+read]

		// Pass to Unix domain socket
		_, err = ls.unix_conn.Write(message)
		if err != nil {
			return
		}
	}
}

func (ls *ListenSSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from Unix domain socket
		read, err := ls.unix_conn.Read(buffer[:STREAM_HDR_SIZE])
		if err != nil || read < STREAM_HDR_SIZE {
			return
		}
		msglen := uint(binary.LittleEndian.Uint32(buffer[0:4]))
		if msglen > uint(len(buffer)) {
			return
		}
		read, err = ls.unix_conn.Read(buffer[:msglen])
		if err != nil || read < ADDR_HDR_SIZE {
			continue
		}

		// Parse destination from header
		var to pan.UDPAddr
		to.IA = (pan.IA)(binary.BigEndian.Uint64(buffer[:8]))
		addr_len := binary.LittleEndian.Uint32(buffer[8:12])
		if addr_len == 4 {
			to.IP = netip.AddrFrom4(*(*[4]byte)(buffer[12:16]))
		} else if addr_len == 16 {
			to.IP = netip.AddrFrom16(*(*[16]byte)(buffer[12:28]))
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

//////////////////////
// ConnSSockAdapter //
//////////////////////

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
//export PanNewConnSSockAdapter
func PanNewConnSSockAdapter(
	pan_conn C.PanConn, listen_addr *C.cchar_t,
	adapter *C.PanConnSSockAdapter) C.PanError {

	ls, err := NewConnSSockAdapter(
		cgo.Handle(pan_conn).Value().(pan.Conn),
		C.GoString(listen_addr))
	if err != nil {
		return C.PAN_ERR_FAILED
	}

	ptr := (*C.PanConnSSockAdapter)(unsafe.Pointer(adapter))
	*ptr = C.PanConnSSockAdapter(cgo.NewHandle(ls))
	return C.PAN_ERR_OK
}

/**
\brief Close the Unix domain socket **and the PAN connection**.
\ingroup adapter
*/
//export PanConnSSockAdapterClose
func PanConnSSockAdapterClose(adapter C.PanConnSSockAdapter) C.PanError {
	ls := cgo.Handle(adapter).Value().(*ConnSSockAdapter)
	ls.Close()
	return C.PAN_ERR_OK
}

type ConnSSockAdapter struct {
	pan_conn      pan.Conn
	unix_listener *net.UnixListener
	unix_conn     *net.UnixConn
}

func NewConnSSockAdapter(
	pan_conn pan.Conn, listen_addr string) (*ConnSSockAdapter, error) {

	listen, err := net.ResolveUnixAddr("unix", listen_addr)
	if err != nil {
		return nil, err
	}

	os.Remove(listen_addr)
	unix_listener, err := net.ListenUnix("unix", listen)
	if err != nil {
		return nil, err
	}
	unix_listener.SetUnlinkOnClose(true)

	adapter := &ConnSSockAdapter{
		pan_conn:      pan_conn,
		unix_listener: unix_listener,
		unix_conn:     nil,
	}

	go adapter.waitForConn()

	return adapter, nil
}

func (cs *ConnSSockAdapter) waitForConn() {
	conn, err := cs.unix_listener.AcceptUnix()
	defer cs.unix_listener.Close()
	if err != nil {
		return
	}
	cs.unix_conn = conn
	go cs.panToUnix()
	go cs.unixToPan()
}

func (cs *ConnSSockAdapter) Close() error {
	cs.pan_conn.Close()
	cs.unix_conn.Close()
	return nil
}

func (cs *ConnSSockAdapter) panToUnix() {
	var buffer = make([]byte, 4096)
	for {
		// Read from network
		read, err := cs.pan_conn.Read(buffer[STREAM_HDR_SIZE:])
		if err != nil {
			return
		}

		// Pass to Unix domain socket
		binary.LittleEndian.PutUint32(buffer[0:4], uint32(read))
		_, err = cs.unix_conn.Write(buffer[:STREAM_HDR_SIZE+read])
		if err != nil {
			return
		}
	}
}

func (cs *ConnSSockAdapter) unixToPan() {
	var buffer = make([]byte, 4096)
	for {
		// Read from Unix domain socket
		read, err := cs.unix_conn.Read(buffer[:STREAM_HDR_SIZE])
		if err != nil || read < STREAM_HDR_SIZE {
			return
		}
		msglen := uint(binary.LittleEndian.Uint32(buffer[0:4]))
		if msglen > uint(len(buffer)) {
			return
		}
		read, err = cs.unix_conn.Read(buffer[:msglen])
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

//////////
// main //
//////////

func main() {
}
