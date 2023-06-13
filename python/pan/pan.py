# Copyright 2023 Lars-Christian Schulz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress
from abc import ABC, abstractmethod
from ctypes import *
from ctypes.util import find_library
from typing import Iterable, List, Tuple

MAX_PACKET_SIZE = 2048


##################
# Load Libraries #
##################

_libc = CDLL(find_library("c"))

PAN_LIBRARY_NAME = "pan"
_libpan_path = find_library(PAN_LIBRARY_NAME)
if _libpan_path is None:
    raise RuntimeError("Can't find library " + PAN_LIBRARY_NAME)
_libpan = CDLL(_libpan_path)


##################
# Error Handling #
##################

_ERR_OK = 0
_ERR_FAILED = 1
_ERR_DEADLINE = 2
_ERR_NO_PATH = 3
_ERR_ADDR_SYNTAX = 4
_ERR_ADDR_RESOLUTION = 5

class PanError(Exception):
    pass

class OperationFailed(PanError):
    pass

class DeadlineExceeded(PanError):
    pass

class NoPath(PanError):
    pass

class InvalidAddrSyntax(PanError):
    pass

class AddrResolutionFailed(PanError):
    pass

def _raise_if_error(err):
    if err == _ERR_FAILED:
        raise OperationFailed("Requested operation failed")
    elif err == _ERR_DEADLINE:
        raise DeadlineExceeded("I/O deadline exceeded")
    elif err == _ERR_NO_PATH:
        raise NoPath("No path to destination is known")
    elif err == _ERR_ADDR_SYNTAX:
        raise InvalidAddrSyntax("Invalid address syntax")
    elif err == _ERR_ADDR_RESOLUTION:
        raise AddrResolutionFailed("Address resolution failed")


##################
# Callback Types #
##################

_PolicyFilterFn = CFUNCTYPE(c_void_p, POINTER(c_void_p), c_size_t, c_void_p)

class _PathSelectorCB(Structure):
    PathFn       = CFUNCTYPE(c_void_p, c_void_p)
    InitializeFn = CFUNCTYPE(None, c_void_p, c_void_p, POINTER(c_void_p), c_size_t, c_void_p)
    RefreshFn    = CFUNCTYPE(None, POINTER(c_void_p), c_size_t, c_void_p)
    PathDownFn   = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)
    CloseFn      = CFUNCTYPE(None, c_void_p)
    _fields_ = [
        ("path",       PathFn),
        ("initialize", InitializeFn),
        ("refresh",    RefreshFn),
        ("path_down",  PathDownFn),
        ("close",      CloseFn)
    ]

class _ReplySelectorCB(Structure):
    PathFn       = CFUNCTYPE(c_void_p, c_void_p, c_void_p)
    InitializeFn = CFUNCTYPE(None, c_void_p, c_void_p)
    RecordFn     = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)
    PathDownFn   = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)
    CloseFn      = CFUNCTYPE(None, c_void_p)
    _fields_ = [
        ("path",       PathFn),
        ("initialize", InitializeFn),
        ("record",     RecordFn),
        ("path_down",  PathDownFn),
        ("close",      CloseFn),
    ]


######################
# Imported Functions #
######################

_free = _libc.free
_free.argtypes = [c_void_p]
_free.restype = None

_duplicate_handle = _libpan.PanDuplicateHandle
_duplicate_handle.argtypes = [c_void_p]
_duplicate_handle.restype = c_void_p

_delete_handle = _libpan.PanDeleteHandle
_delete_handle.argtypes = [c_void_p]
_delete_handle.restype = None

_udp_addr_new = _libpan.PanUDPAddrNew
_udp_addr_new.argtypes = [POINTER(c_uint64), POINTER(c_ubyte), c_int, c_uint16]
_udp_addr_new.restype = c_void_p

_udp_addr_get_ia = _libpan.PanUDPAddrGetIA
_udp_addr_get_ia.argtypes = [c_void_p, POINTER(c_uint64)]
_udp_addr_get_ia.restype = None

_udp_addr_is_ipv6 = _libpan.PanUDPAddrIsIPv6
_udp_addr_is_ipv6.argtypes = [c_void_p]
_udp_addr_is_ipv6.restype = c_int

_udp_addr_get_ipv4 = _libpan.PanUDPAddrGetIPv4
_udp_addr_get_ipv4.argtypes = [c_void_p, 4*c_ubyte]
_udp_addr_get_ipv4.restype = c_uint32

_udp_addr_get_ipv6 = _libpan.PanUDPAddrGetIPv6
_udp_addr_get_ipv6.argtypes = [c_void_p, 16*c_ubyte]
_udp_addr_get_ipv6.restype = c_uint32

_udp_addr_get_port = _libpan.PanUDPAddrGetPort
_udp_addr_get_port.argtypes = [c_void_p]
_udp_addr_get_port.restype = c_uint16

_udp_addr_to_string = _libpan.PanUDPAddrToString
_udp_addr_to_string.argtypes = [c_void_p]
_udp_addr_to_string.restype = c_void_p

_path_to_string = _libpan.PanPathToString
_path_to_string.argtypes = [c_void_p]
_path_to_string.restype = c_void_p

_path_get_fingerprint = _libpan.PanPathGetFingerprint
_path_get_fingerprint.argtypes = [c_void_p]
_path_get_fingerprint.restype = c_void_p

_path_contains_interface = _libpan.PanPathContainsInterface
_path_contains_interface.argtypes = [c_void_p]
_path_contains_interface.restype = c_int

_path_fingerprint_are_equal = _libpan.PanPathFingerprintAreEqual
_path_fingerprint_are_equal.argtypes = [c_void_p, c_void_p]
_path_fingerprint_are_equal.restype = c_int

_new_c_policy = _libpan.PanNewCPolicy
_new_c_policy.argtypes = [_PolicyFilterFn, c_void_p]
_new_c_policy.restype = c_void_p

_new_c_selector = _libpan.PanNewCSelector
_new_c_selector.argtypes = [POINTER(_PathSelectorCB), c_void_p]
_new_c_selector.restype = c_void_p

_new_c_reply_selector = _libpan.PanNewCReplySelector
_new_c_reply_selector.argtypes = [POINTER(_ReplySelectorCB), c_void_p]
_new_c_reply_selector.restype = c_void_p

_path_contains_interface.argtypes = [c_void_p]
_path_contains_interface.restype = c_int


##########
# Public #
##########

class OwningHandle:
    def __init__(self, handle: int|c_void_p):
        if isinstance(handle, int):
            self._handle = handle
        elif isinstance(handle, c_void_p):
            self._handle = handle.value
        else:
            assert False

    def __del__(self):
        # best effort cleanup
        self.delete()

    @property
    def _as_parameter_(self) -> int:
        assert self._handle is not None
        return self._handle

    @property
    def handle(self) -> int:
        return self._handle

    def delete(self):
        if self._handle is not None:
            _delete_handle(self._handle)
            self._handle = None

    def copy(self) -> 'OwningHandle':
        return OwningHandle(_duplicate_handle(self._handle))


class Handle:
    def __init__(self, handle: int|c_void_p):
        if isinstance(handle, int):
            self._handle = handle
        elif isinstance(handle, c_void_p):
            self._handle = handle.value
        else:
            assert False

    @property
    def _as_parameter_(self) -> c_void_p:
        assert self._handle is not None
        return self._handle

    @property
    def handle(self) -> int:
        return self._handle

    def delete(self):
        self._handle = None

    def copy(self) -> OwningHandle:
        return OwningHandle(_duplicate_handle(self._handle))


class UDPAddress:
    def __init__(self, handle: Handle|OwningHandle):
        assert isinstance(handle, (Handle, OwningHandle))
        self._handle = handle

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    @staticmethod
    def build(isd: int, asn: int,
              ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
              port: int) -> 'UDPAddress':
        """Build a UDP address from ISD, ASN, IP, and port."""
        ia = c_uint64(int.from_bytes((asn | (isd << 48)).to_bytes(8, 'big'), 'little'))
        buf = (16*c_ubyte)(*ip.packed)
        ip_len = 4 if ip.version == 4 else 16
        new_addr = _udp_addr_new(byref(ia), buf, ip_len, port)
        return UDPAddress(OwningHandle(new_addr))

    def __str__(self):
        ptr = _udp_addr_to_string(self._handle)
        if not ptr:
            raise PanError("Converting UDPAddress to string failed")
        result = string_at(ptr)
        _free(ptr)
        return result.decode()

    def get_ia(self) -> Tuple[int, int]:
        """Get the ISD, ASN pair."""
        ia = c_uint64()
        _udp_addr_get_ia(self._handle, byref(ia))
        buf = bytes(ia)
        isd = int.from_bytes(buf[:2], byteorder='big')
        asn = int.from_bytes(buf[2:], byteorder='big')
        return (isd, asn)

    def get_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Get the host IP address."""
        if _udp_addr_is_ipv6(self._handle) == 0:
            addr = (4*c_ubyte)()
            err = _udp_addr_get_ipv4(self._handle, addr)
            _raise_if_error(err)
            return ipaddress.ip_address(int.from_bytes(bytes(addr), 'big'))
        else:
            addr = (16*c_ubyte)()
            err = _udp_addr_get_ipv6(self._handle, addr)
            _raise_if_error(err)
            return ipaddress.ip_address(int.from_bytes(bytes(addr), 'big'))

    def get_port(self) -> int:
        """Get the UDP port."""
        return int(_udp_addr_get_port(self._handle))


class PathInterface:
    def __init__(self, handle: Handle|OwningHandle):
        assert isinstance(handle, (Handle, OwningHandle))
        self._handle = handle

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle


class PathFingerprint:
    def __init__(self, handle: Handle|OwningHandle):
        assert isinstance(handle, (Handle, OwningHandle))
        self._handle = handle

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    def __eq__(self, other):
        if not isinstance(other, PathFingerprint):
            return False
        if _path_fingerprint_are_equal(self._handle, other._handle) != 0:
            return True
        else:
            return False

    def __nq__(self, other):
        return not (self == other)


class Path:
    def __init__(self, handle: Handle|OwningHandle):
        assert isinstance(handle, (Handle, OwningHandle))
        self._handle = handle

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    def __str__(self):
        ptr = _path_to_string(self._handle)
        if not ptr:
            raise PanError("Converting Path to string failed")
        result = string_at(ptr)
        _free(ptr)
        return result.decode()

    def __contains__(self, interface):
        if not isinstance(interface, PathInterface):
            return False
        if _path_contains_interface(self._handle, interface._handle) != 0:
            return True
        else:
            return False

    def fingerprint(self) -> PathFingerprint:
        return PathFingerprint(OwningHandle(_path_get_fingerprint(self._handle)))


class PathPolicy(ABC):
    def __init__(self):
        def _filter(paths, count, user):
            pypaths = [Path(Handle(path)) for path in paths[:count]]
            filtered = self.filter(pypaths)
            try:
                assert len(filtered) <= count
                for i, path in enumerate(filtered):
                    assert isinstance(path, Path)
                    handle = path._handle.handle
                    assert isinstance(handle, int)
                    paths[i] = handle
                return len(filtered)
            except AssertionError:
                return

        self._callback = _PolicyFilterFn(_filter)
        self._handle = OwningHandle(_new_c_policy(self._callback, None))

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    def delete(self):
        self._handle.delete()

    @abstractmethod
    def filter(self, paths: List[Path]) -> Iterable[Path]:
        pass


class PathSelector(ABC):
    def __init__(self):
        def _path(user):
            result = self.path()
            if isinstance(result, Path):
                handle = result._handle.handle
                if isinstance(handle, int):
                    return handle
            return 0 # invalid handle, will panic in Go

        def _initialize(local, remote, paths, count, user):
            self.initialize(
                UDPAddress(OwningHandle(local)),
                UDPAddress(OwningHandle(remote)),
                [Path(OwningHandle(path)) for path in paths[:count]]
            )

        def _refresh(paths, count, user):
            self.refresh([Path(OwningHandle(path)) for path in paths[:count]])

        def _path_down(pf, pi, user):
            self.path_down(
                PathFingerprint(OwningHandle(pf)),
                PathInterface(OwningHandle(pi)),
            )

        self._callbacks = _PathSelectorCB(
            _PathSelectorCB.PathFn(_path),
            _PathSelectorCB.InitializeFn(_initialize),
            _PathSelectorCB.RefreshFn(_refresh),
            _PathSelectorCB.PathDownFn(_path_down),
            _PathSelectorCB.CloseFn(lambda _: self.close())
        )
        self._handle = OwningHandle(_new_c_selector(byref(self._callbacks), None))

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    def delete(self):
        self._handle.delete()

    @abstractmethod
    def path(self) -> Path:
        pass

    @abstractmethod
    def initialize(self, local: UDPAddress, remote: UDPAddress, paths: List[Path]) -> None:
        pass

    @abstractmethod
    def refresh(self, paths: List[Path]) -> None:
        pass

    @abstractmethod
    def path_down(self, pf: PathFingerprint, pi: PathInterface) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class ReplySelector(ABC):
    def __init__(self):
        def _path(remote, user):
            result = self.path(UDPAddress(OwningHandle(remote)))
            if isinstance(result, Path):
                handle = result._handle.handle
                if isinstance(handle, int):
                    return handle
            return 0 # invalid handle, will panic in Go

        def _initialize(local, user):
            self.initialize(UDPAddress(OwningHandle(local)))

        def _record(remote, path, user):
            self.record(
                UDPAddress(OwningHandle(remote)),
                Path(OwningHandle(path))
            )

        def _path_down(pf, pi, user):
            self.path_down(
                PathFingerprint(OwningHandle(pf)),
                PathInterface(OwningHandle(pi)),
            )

        self._callbacks = _ReplySelectorCB(
            _ReplySelectorCB.PathFn(_path),
            _ReplySelectorCB.InitializeFn(_initialize),
            _ReplySelectorCB.RecordFn(_record),
            _ReplySelectorCB.PathDownFn(_path_down),
            _ReplySelectorCB.CloseFn(lambda _: self.close())
        )
        self._handle = OwningHandle(_new_c_reply_selector(byref(self._callbacks), None))

    @property
    def _as_parameter_(self) -> int:
        return self._handle.handle

    def delete(self):
        self._handle.delete()

    @abstractmethod
    def path(self, remote: UDPAddress) -> Path:
        pass

    @abstractmethod
    def initialize(self, local: UDPAddress) -> None:
        pass

    @abstractmethod
    def record(self, remote: UDPAddress, path: Path) -> None:
        pass

    @abstractmethod
    def path_down(self, pf: PathFingerprint, pi: PathInterface) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass
