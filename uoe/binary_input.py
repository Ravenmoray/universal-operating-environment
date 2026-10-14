"""Range-checked reads shared by static dependency parsers."""
class BinaryError(ValueError):
    pass


class StringError(BinaryError):
    """A NUL-terminated string that is unterminated within its limit or region."""


class Reader:
    def __init__(self, stream, size, budget=8_000_000):
        self.stream, self.size, self.remaining = stream, size, budget

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset > self.size or size > self.size - offset:
            raise BinaryError('binary range outside file')
        if size > self.remaining:
            raise BinaryError('binary inspection read budget exceeded')
        self.remaining -= size
        self.stream.seek(offset)
        data = self.stream.read(size)
        if len(data) != size:
            raise BinaryError('truncated binary range')
        return data

    def cstring(self, offset, available, limit, chunk=64):
        """Read a NUL-terminated string of at most ``limit`` bytes, without the NUL.

        ``available`` is how many bytes may be read from ``offset`` (the end of the
        enclosing region). Reads in small chunks so the read budget is charged for
        the bytes actually consumed, not for the worst-case name length; otherwise
        thousands of short names would exhaust the budget long before any documented
        count limit.
        """
        out = bytearray()
        while len(out) <= limit:
            want = min(chunk, available - len(out), limit + 1 - len(out))
            if want <= 0:
                break
            data = self.read(offset + len(out), want)
            end = data.find(b'\0')
            if end >= 0:
                out += data[:end]
                return bytes(out)
            out += data
        raise StringError('unterminated or overlong string')
