#!/usr/bin/env python
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

import argparse
import asyncio
import os
import threading
from typing import Iterable, List

import pan
from pan import Path, PathFingerprint, PathInterface, UDPAddress, udp


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--local", default=None,
                        help="Local IP address and port (required for servers)")
    parser.add_argument("-r", "--remote", default=None,
                        help="Scion address of the remote server (only for clients)")
    parser.add_argument("-m", "--message", type=str, default="Hello!",
                        help="The message clients will send to the server")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of messages to send")
    parser.add_argument("-i", "--interactive", action='store_true',
                        help="Prompt for path selection (client only)")
    parser.add_argument("-s", "--show-path", action='store_true',
                        help="Print the paths taken by each packet")
    parser.add_argument("-q", "--quiet", action='store_true',
                         help="Only print response from server (client only)")
    parser.add_argument("-a", "--async", action='store_true', dest='async_',
                        help="Use Unix sockets for asynchronous IO")
    args = parser.parse_args()

    # Check for mandatory options
    if not args.local and not args.remote:
        raise RuntimeError(
            "At least one of local (for servers) and remote (for clients) is required")

    return args


class InteractivePathPolicy(pan.PathPolicy):
    def __init__(self):
        super().__init__()
        self._sel_path_fp = None

    def filter(self, paths: List[Path]) -> Iterable[Path]:
        if self._sel_path_fp is None:
            while True:
                for i, path in enumerate(paths):
                    print("[{}] {}".format(i, str(path)))
                try:
                    selection = int(input("Choose path: "))
                except ValueError:
                    print("Invalid selection")
                    continue
                if 0 <= selection < len(paths):
                    self._sel_path_fp = paths[i].fingerprint()
                    break
                else:
                    print("Invalid selection")

        def filter_func(path):
            return path.fingerprint() == self._sel_path_fp
        filtered = list(filter(filter_func, paths))

        if len(paths) == 0:
            return paths
        else:
            return filtered


class DefaultPathSelector(pan.PathSelector):
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._paths = []
        self._curr_path = None

    def path(self) -> Path:
        with self._lock:
            return self._curr_path

    def initialize(self, local: UDPAddress, remote: UDPAddress, paths: List[Path]) -> None:
        with self._lock:
            self._paths = paths
            self._curr_path = paths[0]

    def refresh(self, paths: List[Path]) -> None:
        with self._lock:
            curr_fp = self._curr_path.fingerprint()
            for path in paths:
                if path.fingerprint() == curr_fp:
                    self.curr_path = path
                    break
            self.paths = paths

    def path_down(self, pf: PathFingerprint, pi: PathInterface) -> None:
        with self._lock:
            paths = self._paths
            if self._curr_path.fingerprint() == pf or pi in self._curr_path:
                if len(paths) > 0:
                    self._curr_path = paths[(paths.index(self._curr_path) + 1) % len(paths)]
                else:
                    self._curr_path = None

    def close(self) -> None:
        pass


class DefaultReplySelector(pan.ReplySelector):
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._remotes = {}

    def path(self, remote: UDPAddress) -> Path:
        with self._lock:
            try:
                return self._remotes[str(remote)]
            except KeyError:
                return None # should never happen

    def initialize(self, local: UDPAddress) -> None:
        pass

    def record(self, remote: UDPAddress, path: Path) -> None:
        with self._lock:
            self._remotes[str(remote)] = path

    def path_down(self, pf: PathFingerprint, pi: PathInterface) -> None:
        pass

    def close(self) -> None:
        pass


def run_server(args):
    selector = DefaultReplySelector()

    with udp.ListenConn(args.local, selector) as conn:
        print("Server listening at", conn.local())

        while True:
            path = None
            while True:
                # Give the interpreter a chance to run every 100ms.
                conn.set_deadline(0.1)
                try:
                    if args.show_path:
                        msg, from_addr, path = conn.read_from_via()
                        break
                    else:
                        msg, from_addr = conn.read_from()
                        break
                except pan.DeadlineExceeded:
                    pass

            print(f"Received {len(msg)} bytes from {from_addr}:")
            print(msg)
            if path is not None:
                print("Path:", path)

            conn.write_to(msg, from_addr)


async def run_server_async(args):
    GO_SOCK = "/tmp/scion_async_server_go.sock"
    PY_SOCK = "/tmp/scion_async_server.sock"

    loop = asyncio.get_event_loop()
    conn = sock_adapter = sock = None

    try:
        conn = udp.ListenConn(args.local)
        try:
            os.remove(PY_SOCK)
        except FileNotFoundError:
            pass
        sock_adapter = udp.ListenSockAdapter(conn, GO_SOCK, PY_SOCK)
        sock = sock_adapter.create_socket()
        sock.setblocking(False)
        print("Server listening at", conn.local())

        while True:
            msg = await loop.sock_recv(sock, 2048)
            print(msg[32:])
            await loop.sock_sendall(sock, msg)

    finally:
        if sock is not None:
            sock.close()
        if sock_adapter is not None:
            sock_adapter.close()
            try:
                os.remove(PY_SOCK)
            except FileNotFoundError:
                pass
        if conn is not None:
            conn.close()


def run_client(args):
    remote = udp.resolveUDPAddr(args.remote)

    policy = None
    if args.interactive:
        policy = InteractivePathPolicy()
    selector = DefaultPathSelector()

    with udp.Conn(remote, args.local, policy, selector) as conn:
        for i in range(args.count):
            conn.write(args.message.encode())

            path = None
            conn.set_deadline(1)
            if args.show_path:
                msg, path = conn.read_via()
            else:
                msg = conn.read()

            if not args.quiet:
                print(f"Received {len(msg)} bytes:")
            print(msg)
            if not args.quiet and path is not None:
                print("Path:", path)


async def run_client_async(args):
    GO_SOCK = "/tmp/scion_async_client_go.sock"
    PY_SOCK = "/tmp/scion_async_client.sock"

    policy = None
    if args.interactive:
        policy = InteractivePathPolicy()
    selector = DefaultPathSelector()

    loop = asyncio.get_event_loop()
    conn = sock_adapter = sock = None
    try:
        remote = udp.resolveUDPAddr(args.remote)
        conn = udp.Conn(remote, args.local, policy, selector)
        try:
            os.remove(PY_SOCK)
        except FileNotFoundError:
            pass
        sock_adapter = udp.ConnSockAdapter(conn, GO_SOCK, PY_SOCK)
        sock = sock_adapter.create_socket()
        sock.setblocking(False)

        buffer = args.message.encode()
        for i in range(args.count):
            await loop.sock_sendall(sock, buffer)

            msg = await loop.sock_recv(sock, 2048)
            if not args.quiet:
                print(f"Received {len(msg)} bytes:")
            print(msg)

    finally:
        if sock is not None:
            sock.close()
        if sock_adapter is not None:
            sock_adapter.close()
            try:
                os.remove(PY_SOCK)
            except FileNotFoundError:
                pass
        if conn is not None:
            conn.close()


def main():
    try:
        args = parse_args()

        if args.remote:
            if not args.async_:
                run_client(args)
            else:
                asyncio.run(run_client_async(args))
        else:
            if not args.async_:
                run_server(args)
            else:
                asyncio.run(run_server_async(args))

    except pan.PanError as e:
        print("PAN error:", e)


if __name__ == "__main__":
    main()
