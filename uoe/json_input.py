"""Size-bounded strict JSON input for experimental graph and claim documents."""
import json
from pathlib import Path


def load_document(path, max_bytes, error_type=ValueError):
    # Bound the actual read, not a racy stat followed by an unlimited read.
    with Path(path).open('rb') as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise error_type('JSON file exceeds experimental byte limit')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise error_type('duplicate JSON object key')
            result[key] = value
        return result

    def invalid_constant(value):
        raise error_type('non-finite JSON number')

    # Reject extreme nesting before allocating deeply nested objects. Count only
    # structural brackets outside strings, accounting for escaped backslashes.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                raise error_type('JSON nesting exceeds experimental depth limit')
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise error_type('invalid JSON document: ' + str(exc)) from exc
