import re

_LEAD = re.compile(r"^\s*[vV]?(\d+(?:\.\d+)*(?:p\d+)?)")
BACKPORT_HINT = re.compile(r"ubuntu|debian|\+deb|\.el\d|\bel\d|\.fc\d|centos|red ?hat|rhel|suse|alpine", re.I)


def vtuple(v: str | None):
    """Leading version token -> tuple of ints. '8.9p1 Ubuntu 3' -> (8, 9, 1). None if unparseable."""
    if not v:
        return None
    m = _LEAD.match(v)
    if not m:
        return None
    return tuple(int(x) for x in re.findall(r"\d+", m.group(1)))


def _cmp(a, b):
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version, exact=None, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    """True/False, or None when the installed version cannot be parsed."""
    v = vtuple(version)
    if v is None:
        return None
    if exact:
        e = vtuple(exact)
        return e is not None and _cmp(v, e) == 0
    for bound, test in ((start_incl, lambda c: c >= 0), (start_excl, lambda c: c > 0),
                        (end_incl, lambda c: c <= 0), (end_excl, lambda c: c < 0)):
        if bound:
            b = vtuple(bound)
            if b is None or not test(_cmp(v, b)):
                return False
    return True
