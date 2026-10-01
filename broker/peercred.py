"""Peer uid of a connected Unix-domain socket (macOS LOCAL_PEERCRED, Linux SO_PEERCRED)."""

from __future__ import annotations

import socket
import struct
import sys

SOL_LOCAL = 0
LOCAL_PEERCRED = 0x001
XUCRED_VERSION = 0
# struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups;
#                 gid_t cr_groups[NGROUPS(16)]; }  -> 4 + 4 + 2 (+2 pad) + 64
XUCRED_SIZE = 76
_UCRED = struct.Struct("=iII")  # Linux struct ucred { pid_t; uid_t; gid_t; }


def parse_xucred(data: bytes) -> int:
    """The ``cr_uid`` of a macOS ``struct xucred``; ValueError if malformed."""
    if len(data) < 8:
        raise ValueError("xucred too short")
    version, uid = struct.unpack_from("=II", data, 0)
    if version != XUCRED_VERSION:
        raise ValueError(f"unexpected xucred version {version}")
    return int(uid)


def peer_uid(sock: socket.socket) -> int:
    """The effective uid of the process on the other end of `sock`."""
    if sys.platform == "darwin":
        return parse_xucred(sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, XUCRED_SIZE))
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is None:
        raise OSError("no peer-credential API on this platform")
    _pid, uid, _gid = _UCRED.unpack(
        sock.getsockopt(socket.SOL_SOCKET, so_peercred, _UCRED.size)
    )
    return int(uid)
