"""Safety limits for decompressing untrusted XDW data."""

from __future__ import annotations

from dataclasses import dataclass, fields

from .errors import XdwLimitError
from .lzh import decompress_lzh


@dataclass(frozen=True)
class XdwLimits:
    """Upper bounds applied while decoding LZH streams and images.

    Sizes are decoded bytes.  ``max_total_decoded`` caps the sum of LZH output
    produced for one :class:`XdwReader` and the objects it returns (pages,
    resources, generations); a cached result is counted once.  It is not a
    limit on process memory: copies, BMP/TIFF assembly and Python overhead are
    not counted, and peak memory of one decode is about twice its output.
    """

    max_lzh_output: int = 64 << 20
    max_metadata: int = 16 << 20
    max_annotation_emf: int = 16 << 20
    max_image_bytes: int = 512 << 20
    max_image_dimension: int = 65_535
    max_total_decoded: int = 1 << 30

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{item.name} must be an int")
            if not 1 <= value <= (1 << 62):
                raise ValueError(f"{item.name} must be between 1 and 2**62")


class _DecodeBudget:
    """Applies one reader's limits and counts the bytes it has decoded."""

    def __init__(self, limits: XdwLimits | None = None) -> None:
        self.limits = limits if limits is not None else XdwLimits()
        self.used = 0

    def require(self, name: str, size: int) -> None:
        """Refuse a declared size before anything is allocated for it."""
        limit = getattr(self.limits, name)
        if size > limit:
            raise XdwLimitError(f"declared size {size} exceeds {name}={limit}",
                                limit_name=name, limit=limit, requested=size)

    def decompress(self, data: bytes, expected_size: int | None, name: str) -> bytes:
        """Decode within the per-stream limit *name* and the remaining budget."""
        if expected_size is not None:
            self.require(name, expected_size)
            self.require("max_lzh_output", expected_size)
        remaining = self.limits.max_total_decoded - self.used
        if expected_size is not None and expected_size > remaining:
            raise XdwLimitError(
                f"decoding {expected_size} more bytes exceeds max_total_decoded="
                f"{self.limits.max_total_decoded}",
                limit_name="max_total_decoded", limit=self.limits.max_total_decoded,
                requested=self.used + expected_size,
            )
        caps = {name: getattr(self.limits, name),
                "max_lzh_output": self.limits.max_lzh_output,
                "max_total_decoded": remaining}
        tightest = min(caps, key=caps.get)
        try:
            output = decompress_lzh(data, expected_size, max_output=caps[tightest])
        except XdwLimitError as exc:
            limit = (self.limits.max_total_decoded if tightest == "max_total_decoded"
                     else caps[tightest])
            raise XdwLimitError(f"LZH output exceeds {tightest}={limit}",
                                limit_name=tightest, limit=limit,
                                requested=exc.requested) from exc
        self.used += len(output)
        return output


def budget_of(data: bytes) -> _DecodeBudget:
    """The budget of the reader that owns *data*, else a fresh default one."""
    budget = getattr(data, "budget", None)
    return budget if budget is not None else _DecodeBudget()
