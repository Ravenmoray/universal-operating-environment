"""Range-checked reads shared by static dependency parsers."""
class BinaryError(ValueError):
    pass


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
