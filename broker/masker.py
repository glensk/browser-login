"""Streaming output masker: every occurrence of any pattern becomes ``***``.

One ``Masker`` per output stream. It runs ONE Aho-Corasick automaton over the
ORIGINAL bytes (never over already-masked output), unions the match spans of
all patterns (overlapping or touching matches merge into one ``***``) and holds
back only what may still become part of a match: the longest suffix of the
stream that is a prefix of some pattern (the automaton state's depth, at most
``max_pattern_len - 1`` bytes) plus an unfinished mask span. So text that cannot
start a secret — a prompt, a progress line — is released at once. At EOF
(``flush``) the held suffix that is a prefix (>= 1 byte) of any pattern is
masked too: the stream may have been cut inside a secret.

PTY mode (``pty=True``) is for a stream that went through a terminal's output
translation: it also matches the ``\\n`` -> ``\\r\\n`` form of every multi-line
pattern.

The masker covers the given patterns only (see ``broker/variants.py``), not
arbitrary transforms a program may apply to a value.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

REPLACEMENT = b"***"


class _Automaton:  # pylint: disable=too-few-public-methods
    """Aho-Corasick over bytes; per state: depth and longest output length."""

    def __init__(self, patterns: Iterable[bytes]) -> None:
        self.goto: list[dict[int, int]] = [{}]
        self.fail: list[int] = [0]
        self.depth: list[int] = [0]
        self.out: list[int] = [0]  # longest pattern ending in this state
        for pat in patterns:
            self._add(pat)
        self._link()

    def _add(self, pat: bytes) -> None:
        state = 0
        for byte in pat:
            nxt = self.goto[state].get(byte)
            if nxt is None:
                nxt = len(self.goto)
                self.goto.append({})
                self.fail.append(0)
                self.depth.append(self.depth[state] + 1)
                self.out.append(0)
                self.goto[state][byte] = nxt
            state = nxt
        self.out[state] = max(self.out[state], len(pat))

    def _link(self) -> None:
        queue: deque[int] = deque(self.goto[0].values())
        while queue:
            state = queue.popleft()
            for byte, nxt in self.goto[state].items():
                queue.append(nxt)
                f = self.fail[state]
                while f and byte not in self.goto[f]:
                    f = self.fail[f]
                target = self.goto[f].get(byte, 0)
                self.fail[nxt] = target if target != nxt else 0
                self.out[nxt] = max(self.out[nxt], self.out[self.fail[nxt]])

    def step(self, state: int, byte: int) -> int:
        """The state after reading `byte`."""
        while True:
            nxt = self.goto[state].get(byte)
            if nxt is not None:
                return nxt
            if state == 0:
                return 0
            state = self.fail[state]


class Masker:  # pylint: disable=too-many-instance-attributes  # stream state
    """Mask `patterns` in a byte stream fed in arbitrary chunks."""

    def __init__(
        self,
        patterns: Iterable[bytes],
        *,
        pty: bool = False,
        replacement: bytes = REPLACEMENT,
    ) -> None:
        pats = {p for p in patterns if p}
        if pty:
            pats |= {p.replace(b"\n", b"\r\n") for p in pats if b"\n" in p}
        self.patterns = tuple(sorted(pats))
        self.replacement = replacement
        self.max_len = max((len(p) for p in pats), default=0)
        self._ac = _Automaton(pats)
        self._state = 0
        self._buf = bytearray()  # bytes not yet emitted
        self._base = 0  # absolute offset of _buf[0]
        self._total = 0  # absolute offset after the last byte fed
        self._spans: list[list[int]] = []  # merged [start, end) not yet emitted
        self.masked = 0  # merged spans replaced so far
        self._closed = False

    def _add_span(self, start: int, end: int) -> None:
        start = max(start, self._base)
        if self._spans and start <= self._spans[-1][1]:
            last = self._spans[-1]
            last[0] = min(last[0], start)
            last[1] = max(last[1], end)
            # A long match can swallow earlier spans.
            while len(self._spans) > 1 and self._spans[-2][1] >= last[0]:
                prev = self._spans.pop(-2)
                last[0] = min(last[0], prev[0])
        else:
            self._spans.append([start, end])

    def _emit(self, cut: int) -> bytes:
        """Bytes [base, cut) with the spans inside replaced."""
        out = bytearray()
        pos = self._base
        while self._spans and self._spans[0][1] <= cut:
            start, end = self._spans.pop(0)
            out += self._buf[pos - self._base : start - self._base]
            out += self.replacement
            self.masked += 1
            pos = end
        out += self._buf[pos - self._base : cut - self._base]
        del self._buf[: cut - self._base]
        self._base = cut
        return bytes(out)

    def feed(self, data: bytes) -> bytes:
        """Masked output that can be released after `data`."""
        if self._closed:
            raise ValueError("masker already flushed")
        if not self.max_len:
            return bytes(data)
        ac = self._ac
        state = self._state
        pos = self._total
        for byte in data:
            state = ac.step(state, byte)
            longest = ac.out[state]
            if longest:
                self._add_span(pos + 1 - longest, pos + 1)
            pos += 1
        self._state = state
        self._total = pos
        self._buf += data
        # A future match must start inside the longest suffix that is a pattern
        # prefix (the state's depth), so everything before it is final — except
        # a span reaching it, which may still merge with that match.
        cut = self._total - self._ac.depth[state]
        for start, end in self._spans:
            if end >= cut:
                cut = min(cut, start)
                break
        if cut <= self._base:
            return b""
        return self._emit(cut)

    def flush(self) -> bytes:
        """Everything still held, with an EOF fragment of a pattern masked."""
        if self._closed:
            return b""
        self._closed = True
        depth = self._ac.depth[self._state]
        if depth:
            self._add_span(self._total - depth, self._total)
        return self._emit(self._total)


def mask_all(patterns: Iterable[bytes], data: bytes, *, pty: bool = False) -> bytes:
    """One-shot masking of a whole buffer (EOF rules included)."""
    m = Masker(patterns, pty=pty)
    return m.feed(data) + m.flush()
