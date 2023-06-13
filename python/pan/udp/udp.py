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

import socket
from typing import Optional

from ..pan import *
from ..pan import (_ERR_ADDR_RESOLUTION, _ERR_ADDR_SYNTAX, _ERR_DEADLINE,
                   _ERR_FAILED, _ERR_OK, _libpan, _raise_if_error)


######################
# Imported Functions #
######################

_resolve_udp_addr = _libpan.PanResolveUDPAddr
_resolve_udp_addr.argtypes = [c_char_p, POINTER(c_void_p)]
_resolve_udp_addr.restype = c_uint32

_listen_udp = _libpan.PanListenUDP
_listen_udp.argtypes = [c_char_p, c_void_p, POINTER(c_void_p)]
_listen_udp.restype = c_uint32

_listen_conn_read_from = _libpan.PanListenConnReadFrom
_listen_conn_read_from.argtypes = [c_void_p, c_void_p, c_int, POINTER(c_void_p), POINTER(c_int)]
_listen_conn_read_from.restype = c_uint32

_listen_conn_read_from_via = _libpan.PanListenConnReadFromVia
_listen_conn_read_from_via.argtypes = [
    c_void_p, c_void_p, c_int, POINTER(c_void_p), POINTER(c_void_p), POINTER(c_int)]
_listen_conn_read_from_via.restype = c_uint32

_listen_conn_write_to = _libpan.PanListenConnWriteTo
_listen_conn_write_to.argtypes = [c_void_p, c_void_p, c_int, c_void_p, POINTER(c_int)]
_listen_conn_write_to.restype = c_uint32

_listen_conn_write_to_via = _libpan.PanListenConnWriteToVia
_listen_conn_write_to_via.argtypes = [c_void_p, c_void_p, c_int, c_void_p, c_void_p, POINTER(c_int)]
_listen_conn_write_to_via.restype = c_uint32

_listen_conn_local_addr = _libpan.PanListenConnLocalAddr
_listen_conn_local_addr.argtypes = [c_void_p]
_listen_conn_local_addr.restype = c_void_p

_listen_conn_set_deadline = _libpan.PanListenConnSetDeadline
_listen_conn_set_deadline.argtypes = [c_void_p, c_uint32]
_listen_conn_set_deadline.restype = c_uint32

_listen_conn_set_read_deadline = _libpan.PanListenConnSetReadDeadline
_listen_conn_set_read_deadline.argtypes = [c_void_p, c_uint32]
_listen_conn_set_read_deadline.restype = c_uint32

_listen_conn_set_write_deadline = _libpan.PanListenConnSetWriteDeadline
_listen_conn_set_write_deadline.argtypes = [c_void_p, c_uint32]
_listen_conn_set_write_deadline.restype = c_uint32

_listen_conn_close = _libpan.PanListenConnClose
_listen_conn_close.argtypes = [c_void_p]
_listen_conn_close.restype = c_uint32

_dial_udp = _libpan.PanDialUDP
_dial_udp.argtypes = [c_char_p, c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]
_dial_udp.restype = c_uint32

_conn_read = _libpan.PanConnRead
_conn_read.argtypes = [c_void_p, c_void_p, c_int, POINTER(c_int)]
_conn_read.restype = c_uint32

_conn_read_via = _libpan.PanConnReadVia
_conn_read_via.argtypes = [c_void_p, c_void_p, c_int, POINTER(c_void_p), POINTER(c_int)]
_conn_read_via.restype = c_uint32

_conn_write = _libpan.PanConnWrite
_conn_write.argtypes = [c_void_p, c_void_p, c_int, POINTER(c_int)]
_conn_write.restype = c_uint32

_conn_write_via = _libpan.PanConnWriteVia
_conn_write_via.argtypes = [c_void_p, c_void_p, c_int, POINTER(c_void_p), POINTER(c_int)]
_conn_write_via.restype = c_uint32

_conn_local_addr = _libpan.PanConnLocalAddr
_conn_local_addr.argtypes = [c_void_p]
_conn_local_addr.restype = c_void_p

_conn_remote_addr = _libpan.PanConnRemoteAddr
_conn_remote_addr.argtypes = [c_void_p]
_conn_remote_addr.restype = c_void_p

_conn_set_deadline = _libpan.PanConnSetDeadline
_conn_set_deadline.argtypes = [c_void_p, c_uint32]
_conn_set_deadline.restype = c_uint32

_conn_set_read_deadline = _libpan.PanConnSetReadDeadline
_conn_set_read_deadline.argtypes = [c_void_p, c_uint32]
_conn_set_read_deadline.restype = c_uint32

_conn_set_write_deadline = _libpan.PanConnSetWriteDeadline
_conn_set_write_deadline.argtypes = [c_void_p, c_uint32]
_conn_set_write_deadline.restype = c_uint32

_conn_close = _libpan.PanConnClose
_conn_close.argtypes = [c_void_p]
_conn_close.restype = c_uint32

_new_conn_sock_adapter = _libpan.PanNewConnSockAdapter
_new_conn_sock_adapter.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_void_p)]
_new_conn_sock_adapter.restype = c_uint32

_conn_sock_adapter_close = _libpan.PanConnSockAdapterClose
_conn_sock_adapter_close.argtypes = [c_void_p]
_conn_sock_adapter_close.restype = c_uint32

_new_listen_sock_adapter = _libpan.PanNewListenSockAdapter
_new_listen_sock_adapter.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_void_p)]
_new_listen_sock_adapter.restype = c_uint32

_listen_sock_adapter_close = _libpan.PanListenSockAdapterClose
_listen_sock_adapter_close.argtypes = [c_void_p]
_listen_sock_adapter_close.restype = c_uint32


###########
# Private #
###########

def _raise_if_none(conn):
    if not conn:
        raise PanError("Attempting to operate on closed connection")


##########
# Public #
##########

def resolveUDPAddr(address: str) -> UDPAddress:
    resolved = c_void_p()
    err = _resolve_udp_addr(address.encode(), byref(resolved))
    if err == _ERR_ADDR_SYNTAX:
        raise InvalidAddrSyntax(f"Invalid address syntax in '{address}'")
    elif err == _ERR_ADDR_RESOLUTION:
        raise AddrResolutionFailed(f"Cannot resolve '{address}'")
    elif err != _ERR_OK:
        _raise_if_error(err)
    return UDPAddress(OwningHandle(resolved))


class ListenConn:
    def __init__(self, bind: Optional[str] = None,
                 reply_selector: Optional[ReplySelector] = None):
        assert reply_selector is None or isinstance(reply_selector, ReplySelector)
        self._handle = None
        self._reply_selector = reply_selector
        if bind is not None:
            self.listen(bind)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._handle:
            self.close()

    def listen(self, bind: str) -> None:
        conn = c_void_p()
        err = _listen_udp(bind.encode(), self._reply_selector, byref(conn))
        _raise_if_error(err)
        self._handle = OwningHandle(conn)

    def close(self):
        if self._handle is not None:
            _listen_conn_close(self._handle)
            self._handle.delete()
            self._handle = None

    def local(self) -> UDPAddress:
        _raise_if_none(self._handle)
        return UDPAddress(OwningHandle(_listen_conn_local_addr(self._handle)))

    def set_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _listen_conn_set_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def set_read_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _listen_conn_set_read_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def set_write_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _listen_conn_set_write_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def read_from(self) -> Tuple[bytes, UDPAddress]:
        _raise_if_none(self._handle)
        buffer = (c_ubyte * MAX_PACKET_SIZE)()
        from_addr = c_void_p()
        read = c_int()

        err = _listen_conn_read_from(self._handle,
            byref(buffer), sizeof(buffer), byref(from_addr), byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.read_from deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return bytes(buffer[:read.value]), UDPAddress(OwningHandle(from_addr))

    def read_from_via(self) -> Tuple[bytes, UDPAddress, Path]:
        _raise_if_none(self._handle)
        buffer = (c_ubyte * MAX_PACKET_SIZE)()
        from_addr = c_void_p()
        path = c_void_p()
        read = c_int()

        err = _listen_conn_read_from_via(self._handle,
            byref(buffer), sizeof(buffer), byref(from_addr), byref(path), byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.read_from_via deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return (
            bytes(buffer[:read.value]),
            UDPAddress(OwningHandle(from_addr)),
            Path(OwningHandle(path))
        )

    def write_to(self, data: bytes|bytearray, to_addr: UDPAddress) -> int:
        _raise_if_none(self._handle)
        if isinstance(data, bytes):
            data = bytearray(data)
        buffer = (c_ubyte * len(data)).from_buffer(data)
        read = c_int()

        err = _listen_conn_write_to(self._handle,
            buffer, len(buffer), to_addr._handle, byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.write_to deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return read.value

    def write_to_via(self, data: bytes|bytearray, to_addr: UDPAddress, path: Path) -> int:
        _raise_if_none(self._handle)
        if isinstance(data, bytes):
            data = bytearray(data)
        buffer = (c_ubyte * len(data)).from_buffer(data)
        read = c_int()

        err = _listen_conn_write_to_via(self._handle,
            buffer, len(buffer), to_addr._handle, path._handle, byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.write_to deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return read.value


class ListenSockAdapter:
    def __init__(self, listen_conn: ListenConn, go_sock_path: str, py_sock_path: str):
        handle = c_void_p()
        _raise_if_none(listen_conn._handle)
        assert isinstance(listen_conn, ListenConn)
        err = _new_listen_sock_adapter(listen_conn._handle,
                                       go_sock_path.encode(),
                                       py_sock_path.encode(),
                                       byref(handle))
        _raise_if_error(err)
        self._handle = OwningHandle(handle)
        self._go_sock_path = go_sock_path
        self._py_sock_path = py_sock_path

    def close(self):
        if self._handle is not None:
            _listen_sock_adapter_close(self._handle)
            self._handle.delete()
            self._handle = None

    def create_socket(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        try:
            sock.bind(self._py_sock_path)
            sock.connect(self._go_sock_path)
        except:
            sock.close()
            raise
        return sock


class Conn:
    def __init__(self, remote: Optional[UDPAddress] = None,
                 local: Optional[str] = None,
                 policy: Optional[PathPolicy] = None,
                 selector: Optional[PathSelector] = None):
        assert policy is None or isinstance(policy, PathPolicy)
        assert selector is None or isinstance(selector, PathSelector)
        self._handle = None
        self._policy = policy
        self._selector = selector
        if remote is not None:
            self.dial(remote, local)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._handle:
            self.close()

    def dial(self, remote: UDPAddress, local: Optional[str] = None) -> None:
        conn = c_void_p()
        err = _dial_udp(
            local.encode() if local is not None else None,
            remote,
            self._policy, self._selector, byref(conn))
        _raise_if_error(err)
        self._handle = OwningHandle(conn)

    def close(self):
        if self._handle is not None:
            _conn_close(self._handle)
            self._handle.delete()
            self._handle = None

    def local(self) -> UDPAddress:
        _raise_if_none(self._handle)
        return UDPAddress(OwningHandle(_conn_local_addr(self._handle)))

    def remote(self) -> UDPAddress:
        _raise_if_none(self._handle)
        return UDPAddress(OwningHandle(_conn_remote_addr(self._handle)))

    def set_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _conn_set_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def set_read_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _conn_set_read_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def set_write_deadline(self, t: float):
        _raise_if_none(self._handle)
        err = _conn_set_write_deadline(self._handle, c_uint32(int(1000 * t)))
        _raise_if_error(err)

    def read(self) -> bytes:
        _raise_if_none(self._handle)
        buffer = (c_ubyte * MAX_PACKET_SIZE)()
        read = c_int()

        err = _conn_read(self._handle, byref(buffer), sizeof(buffer), byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.read_from deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return bytes(buffer[:read.value])

    def read_via(self) -> Tuple[bytes, Path]:
        _raise_if_none(self._handle)
        buffer = (c_ubyte * MAX_PACKET_SIZE)()
        path = c_void_p()
        read = c_int()

        err = _conn_read_via(self._handle, byref(buffer), sizeof(buffer), byref(path), byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.read_from_via deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return bytes(buffer[:read.value]), Path(OwningHandle(path))

    def write(self, data: bytes|bytearray) -> int:
        _raise_if_none(self._handle)
        if isinstance(data, bytes):
            data = bytearray(data)
        buffer = (c_ubyte * len(data)).from_buffer(data)
        read = c_int()

        err = _conn_write(self._handle, buffer, len(buffer), byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.write_to deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return read.value

    def write_via(self, data: bytes|bytearray, path: Path) -> int:
        _raise_if_none(self._handle)
        if isinstance(data, bytes):
            data = bytearray(data)
        buffer = (c_ubyte * len(data)).from_buffer(data)
        read = c_int()

        err = _conn_write_via(self._handle, buffer, len(buffer), path._handle, byref(read))
        if err == _ERR_DEADLINE:
            raise DeadlineExceeded("ListenConn.write_to deadline exceeded")
        elif err != _ERR_OK:
            _raise_if_error(err)

        return read.value


class ConnSockAdapter:
    def __init__(self, conn: Conn, go_sock_path: str, py_sock_path: str):
        handle = c_void_p()
        _raise_if_none(conn._handle)
        assert isinstance(conn, Conn)
        err = _new_conn_sock_adapter(conn._handle,
                                     go_sock_path.encode(),
                                     py_sock_path.encode(),
                                     byref(handle))
        _raise_if_error(err)
        self._handle = OwningHandle(handle)
        self._go_sock_path = go_sock_path
        self._py_sock_path = py_sock_path

    def close(self):
        if self._handle is not None:
            _conn_sock_adapter_close(self._handle)
            self._handle.delete()
            self._handle = None

    def create_socket(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        try:
            sock.bind(self._py_sock_path)
            sock.connect(self._go_sock_path)
        except:
            sock.close()
            raise
        return sock
