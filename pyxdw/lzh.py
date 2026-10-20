"""Decoder for the raw static-Huffman LZH stream used by observed XDW data.

The stream is the headerless block format commonly associated with LHA's
``-lh4-``/``-lh5-`` methods: canonical Huffman codes describe literals,
match lengths and match distances for each block.  XDW stores the decoded
length in an enclosing TLV field, so no LHA archive header is present.

Parts of the encoder correspond to Haruhiko Okumura's public-domain ar002 and
may be adapted from it; see NOTICE and docs/third_party.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import XdwFormatError, XdwLimitError, XdwUnsupportedFeatureError

DEFAULT_MAX_OUTPUT = 64 << 20


class LzhDecodeError(XdwFormatError, ValueError):
    """Raised when an opaque payload is not a valid supported LZH stream.

    It is an :class:`XdwFormatError`; ``ValueError`` is kept for older callers.
    """


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    def read(self, count: int) -> int:
        if count < 0:
            raise LzhDecodeError("negative bit count")
        if self._position + count > len(self._data) * 8:
            raise LzhDecodeError("truncated LZH bitstream")
        result = 0
        for _ in range(count):
            byte_index, bit_index = divmod(self._position, 8)
            result = (result << 1) | (
                (self._data[byte_index] >> (7 - bit_index)) & 1
            )
            self._position += 1
        return result


class _BitWriter:
    def __init__(self) -> None:
        self._data = bytearray()
        self._current = 0
        self._used = 0

    def write(self, value: int, count: int) -> None:
        if count < 0 or value < 0 or value >= 1 << count:
            raise ValueError("value does not fit in the requested bit count")
        for shift in range(count - 1, -1, -1):
            self._current = (self._current << 1) | ((value >> shift) & 1)
            self._used += 1
            if self._used == 8:
                self._data.append(self._current)
                self._current = 0
                self._used = 0

    def finish(self) -> bytes:
        if self._used:
            self._data.append(self._current << (8 - self._used))
            self._current = 0
            self._used = 0
        return bytes(self._data)


class _HuffmanDecoder:
    def __init__(
        self,
        codes: dict[tuple[int, int], int] | None = None,
        maximum_length: int = 0,
        constant: int | None = None,
    ) -> None:
        self._codes = codes or {}
        self._maximum_length = maximum_length
        self._constant = constant

    @classmethod
    def constant(cls, symbol: int, alphabet_size: int) -> "_HuffmanDecoder":
        if not 0 <= symbol < alphabet_size:
            raise LzhDecodeError("constant Huffman symbol is outside its alphabet")
        return cls(constant=symbol)

    @classmethod
    def from_lengths(cls, lengths: list[int]) -> "_HuffmanDecoder":
        if not lengths or any(length < 0 or length > 16 for length in lengths):
            raise LzhDecodeError("invalid Huffman code lengths")
        maximum = max(lengths)
        if maximum == 0:
            raise LzhDecodeError("Huffman tree has no symbols")

        counts = [0] * (maximum + 1)
        for length in lengths:
            if length:
                counts[length] += 1

        next_code = [0] * (maximum + 1)
        code = 0
        for length in range(1, maximum + 1):
            code = (code + counts[length - 1]) << 1
            if code + counts[length] > 1 << length:
                raise LzhDecodeError("oversubscribed Huffman tree")
            next_code[length] = code

        codes: dict[tuple[int, int], int] = {}
        for symbol, length in enumerate(lengths):
            if not length:
                continue
            symbol_code = next_code[length]
            codes[(length, symbol_code)] = symbol
            next_code[length] += 1
        return cls(codes=codes, maximum_length=maximum)

    def decode(self, reader: _BitReader) -> int:
        if self._constant is not None:
            return self._constant
        code = 0
        for length in range(1, self._maximum_length + 1):
            code = (code << 1) | reader.read(1)
            symbol = self._codes.get((length, code))
            if symbol is not None:
                return symbol
        raise LzhDecodeError("bit pattern is absent from Huffman tree")


def _read_encoded_length(reader: _BitReader) -> int:
    length = reader.read(3)
    if length < 7:
        return length
    while reader.read(1):
        length += 1
        if length > 16:
            raise LzhDecodeError("Huffman code length exceeds 16 bits")
    return length


def _read_auxiliary_tree(
    reader: _BitReader,
    alphabet_size: int,
    count_bits: int,
    special_zero_index: int | None,
) -> _HuffmanDecoder:
    encoded_count = reader.read(count_bits)
    if encoded_count == 0:
        return _HuffmanDecoder.constant(reader.read(count_bits), alphabet_size)
    if encoded_count > alphabet_size:
        raise LzhDecodeError("Huffman length count exceeds alphabet size")

    lengths: list[int] = []
    while len(lengths) < encoded_count:
        lengths.append(_read_encoded_length(reader))
        if special_zero_index is not None and len(lengths) == special_zero_index:
            lengths.extend([0] * reader.read(2))
            if len(lengths) > encoded_count:
                raise LzhDecodeError("special zero run exceeds Huffman length count")
    lengths.extend([0] * (alphabet_size - len(lengths)))
    return _HuffmanDecoder.from_lengths(lengths)


def _read_main_tree(reader: _BitReader, length_tree: _HuffmanDecoder) -> _HuffmanDecoder:
    alphabet_size = 510
    encoded_count = reader.read(9)
    if encoded_count == 0:
        return _HuffmanDecoder.constant(reader.read(9), alphabet_size)
    if encoded_count > alphabet_size:
        raise LzhDecodeError("main Huffman length count exceeds alphabet size")

    lengths: list[int] = []
    while len(lengths) < encoded_count:
        symbol = length_tree.decode(reader)
        if symbol == 0:
            zero_count = 1
        elif symbol == 1:
            zero_count = reader.read(4) + 3
        elif symbol == 2:
            zero_count = reader.read(9) + 20
        else:
            lengths.append(symbol - 2)
            continue
        lengths.extend([0] * zero_count)
        if len(lengths) > encoded_count:
            raise LzhDecodeError("zero run exceeds main Huffman length count")

    lengths.extend([0] * (alphabet_size - len(lengths)))
    return _HuffmanDecoder.from_lengths(lengths)


def decompress_lzh(
    data: bytes,
    expected_size: int | None = None,
    *,
    dictionary_bits: int = 12,
    max_output: int | None = DEFAULT_MAX_OUTPUT,
) -> bytes:
    """Decode one headerless LHA-style static-Huffman stream.

    ``dictionary_bits=12`` corresponds to ``-lh4-`` and is the value observed
    in XDW metadata and resource streams.  Pass 13 explicitly for ``-lh5-``.

    Output never grows beyond ``max_output`` bytes: a larger ``expected_size``
    is refused before decoding, and an undeclared stream stops when it would
    pass the limit.  Both raise :class:`XdwLimitError`.  ``max_output=None``
    removes the limit and lets a small stream allocate gigabytes.
    """

    if dictionary_bits not in (12, 13):
        raise ValueError("dictionary_bits must be 12 or 13")
    if expected_size is not None and expected_size < 0:
        raise ValueError("expected_size must not be negative")
    if max_output is not None:
        if isinstance(max_output, bool) or not isinstance(max_output, int):
            raise TypeError("max_output must be an int or None")
        if max_output < 0:
            raise ValueError("max_output must not be negative")
        if expected_size is not None and expected_size > max_output:
            raise XdwLimitError(
                f"declared LZH size {expected_size} exceeds the {max_output}-byte limit",
                limit_name="max_output", limit=max_output, requested=expected_size,
            )
    # A declared size never exceeds max_output here, so it is the tighter bound.
    bound = expected_size if expected_size is not None else max_output

    def overflow(size: int) -> Exception:
        if expected_size is not None:
            return LzhDecodeError("decoded data exceeds declared size")
        return XdwLimitError(
            f"LZH output exceeds the {max_output}-byte limit",
            limit_name="max_output", limit=max_output, requested=size,
        )

    reader = _BitReader(data)
    output = bytearray()
    while True:
        block_symbols = reader.read(16)
        if block_symbols == 0:
            break

        length_tree = _read_auxiliary_tree(reader, 19, 5, 3)
        main_tree = _read_main_tree(reader, length_tree)
        position_tree = _read_auxiliary_tree(
            reader, dictionary_bits + 1, 4, None
        )

        for _ in range(block_symbols):
            symbol = main_tree.decode(reader)
            if symbol <= 0xFF:
                if bound is not None and len(output) >= bound:
                    raise overflow(len(output) + 1)
                output.append(symbol)
            else:
                match_length = symbol - 253
                position_symbol = position_tree.decode(reader)
                if position_symbol == 0:
                    distance = 0
                else:
                    distance = (1 << (position_symbol - 1)) + reader.read(
                        position_symbol - 1
                    )
                source = len(output) - distance - 1
                if source < 0:
                    raise LzhDecodeError("match points before decoded data")
                if bound is not None and len(output) + match_length > bound:
                    raise overflow(len(output) + match_length)
                for _ in range(match_length):
                    output.append(output[source])
                    source += 1

        # XDW supplies the exact decoded length in its outer resource.  Its raw
        # streams may end immediately after the last block rather than carrying
        # an additional zero-sized LHA block marker.
        if expected_size is not None and len(output) == expected_size:
            return bytes(output)

    if expected_size is not None and len(output) != expected_size:
        raise LzhDecodeError(
            f"decoded size {len(output)} does not match declared {expected_size}"
        )
    return bytes(output)


def compress_lzh_literals(data: bytes, *, dictionary_bits: int = 12) -> bytes:
    """Encode a valid raw LZH stream using literal symbols only.

    This deliberately simple encoder is intended for small XDW metadata
    streams.  It emits a complete 8-bit canonical literal tree, so every input
    byte is encoded as itself.  The result is larger than a normal LH4 stream,
    but remains compatible with the same decoder and avoids speculative match
    generation while the XDW writer is being validated.
    """

    if dictionary_bits not in (12, 13):
        raise ValueError("dictionary_bits must be 12 or 13")

    writer = _BitWriter()
    if not data:
        writer.write(0, 16)
        return writer.finish()

    for block_offset in range(0, len(data), 0xFFFF):
        block = data[block_offset:block_offset + 0xFFFF]
        writer.write(len(block), 16)

        # The auxiliary tree has one constant symbol.  Symbol 10 maps every
        # emitted main-tree entry to a code length of 8 (10 - 2).
        writer.write(0, 5)
        writer.write(10, 5)

        # Define exactly the 256 literal symbols.  With all lengths equal to 8,
        # their canonical codes are the byte values 0x00..0xFF.
        writer.write(256, 9)

        # Matches are never emitted, so a constant zero distance tree suffices.
        writer.write(0, 4)
        writer.write(0, 4)

        for byte in block:
            writer.write(byte, 8)

    return writer.finish()


@dataclass(frozen=True)
class _LzhToken:
    """One LHA code: either a literal or a length/distance pair."""

    symbol: int
    distance: int = 0


def _package_merge_lengths(frequencies: list[int], maximum_length: int) -> list[int]:
    """Construct optimal length-limited codes from positive integer weights.

    Based on Larmore and Hirschberg, *A Fast Algorithm for Optimal
    Length-Limited Huffman Codes*, JACM 37(3), 1990, sections 2-3:
    https://ics.uci.edu/~dhirschb/pubs/LenLimHuff.pdf
    This uses the simple O(nL) package DAG, not the linear-space variant.
    Ties prefer leaves over packages, then symbol order / package creation
    order. Written from the paper, without LHa source or its overflow
    repair; not a formal clean-room implementation. Design and test
    records: docs/third_party.md.
    """
    if not isinstance(maximum_length, int) or not 1 <= maximum_length <= 16:
        raise ValueError("maximum_length must be between 1 and 16")
    if any(not isinstance(weight, int) or weight < 0 for weight in frequencies):
        raise ValueError("frequencies must be nonnegative integers")
    symbols = sorted((i for i, weight in enumerate(frequencies) if weight),
                     key=lambda i: (frequencies[i], i))
    count = len(symbols)
    if count > 1 << maximum_length:
        raise ValueError("too many symbols for maximum_length")
    lengths = [0] * len(frequencies)
    if count < 2:
        if count:
            lengths[symbols[0]] = 1
        return lengths

    # A leaf ID indexes symbols. Larger IDs index pairs in the package DAG.
    leaves = [(frequencies[symbol], i) for i, symbol in enumerate(symbols)]
    pairs: list[tuple[int, int]] = []
    level = leaves
    for _ in range(maximum_length - 1):
        packages = []
        for index in range(0, len(level) - 1, 2):
            first, second = level[index:index + 2]
            node = count + len(pairs)
            pairs.append((first[1], second[1]))
            packages.append((first[0] + second[0], node))
        # Adjacent pair weights are ordered already; merge in linear time.
        merged = []
        leaf_index = package_index = 0
        while leaf_index < count and package_index < len(packages):
            if leaves[leaf_index] <= packages[package_index]:
                merged.append(leaves[leaf_index])
                leaf_index += 1
            else:
                merged.append(packages[package_index])
                package_index += 1
        merged.extend(leaves[leaf_index:])
        merged.extend(packages[package_index:])
        level = merged

    # At width 1/2, 2n-2 items have total width n-1 (the nodeset target).
    pending = [node for _, node in level[:2 * count - 2]]
    while pending:
        node = pending.pop()
        if node < count:
            lengths[symbols[node]] += 1
        else:
            pending.extend(pairs[node - count])
    return lengths


def _huffman_lengths(
    frequencies: list[int], maximum_length: int = 16, *, require_verified: bool = False
) -> list[int]:
    """Return canonical lengths for the compatible static-Huffman encoder.

    Keep the corpus-selected heap/leaf ordering when the tree fits the limit.
    Heap, leaf order and length assignment correspond to ar002 maketree.c
    (public domain). Leaf depths are collected by an iterative traversal
    designed from this function's tree representation and output requirements.
    Over-deep trees use Package-Merge (see _package_merge_lengths) and may
    change stream bytes.
    Writers require verified output and reject that experimental path until
    official API and Viewer validation has been completed.
    """

    if not isinstance(maximum_length, int) or not 1 <= maximum_length <= 16:
        raise ValueError("maximum_length must be between 1 and 16")
    if any(not isinstance(weight, int) or weight < 0 for weight in frequencies):
        raise ValueError("frequencies must be nonnegative integers")
    if sum(weight > 0 for weight in frequencies) > 1 << maximum_length:
        raise ValueError("too many symbols for maximum_length")
    symbol_count = len(frequencies)
    active = [index for index, count in enumerate(frequencies) if count]
    lengths = [0] * symbol_count
    if len(active) <= 1:
        if active:
            lengths[active[0]] = 1
        return lengths

    node_frequencies = frequencies[:] + [0] * (symbol_count - 1)
    left = [0] * (2 * symbol_count - 1)
    right = [0] * (2 * symbol_count - 1)
    heap = [0] + active
    heap_size = len(active)

    def downheap(index: int) -> None:
        nonlocal heap_size
        node = heap[index]
        child = index * 2
        while child <= heap_size:
            if (
                child < heap_size
                and node_frequencies[heap[child]]
                > node_frequencies[heap[child + 1]]
            ):
                child += 1
            if node_frequencies[node] <= node_frequencies[heap[child]]:
                break
            heap[index] = heap[child]
            index = child
            child = index * 2
        heap[index] = node

    for index in range(heap_size // 2, 0, -1):
        downheap(index)

    ordered_leaves: list[int] = []
    available = symbol_count
    root = -1
    while heap_size > 1:
        first = heap[1]
        if first < symbol_count:
            ordered_leaves.append(first)
        heap[1] = heap[heap_size]
        heap_size -= 1
        downheap(1)
        second = heap[1]
        if second < symbol_count:
            ordered_leaves.append(second)
        root = available
        available += 1
        node_frequencies[root] = (
            node_frequencies[first] + node_frequencies[second]
        )
        left[root] = first
        right[root] = second
        heap[1] = root
        downheap(1)

    leaf_counts = [0] * (maximum_length + 1)
    exceeds_limit = False
    pending_nodes = [(root, 0)]
    while pending_nodes:
        node, depth = pending_nodes.pop()
        if node < symbol_count:
            if depth > maximum_length:
                exceeds_limit = True
            else:
                leaf_counts[depth] += 1
            continue
        child_depth = depth + 1
        pending_nodes.append((left[node], child_depth))
        pending_nodes.append((right[node], child_depth))

    if exceeds_limit:
        if require_verified:
            raise XdwUnsupportedFeatureError(
                "Length-limited Package-Merge output is not yet verified with "
                "the official DocuWorks API and Viewer"
            )
        return _package_merge_lengths(frequencies, maximum_length)

    cursor = 0
    for depth in range(maximum_length, 0, -1):
        for _ in range(leaf_counts[depth]):
            lengths[ordered_leaves[cursor]] = depth
            cursor += 1
    return lengths


def _canonical_codes(lengths: list[int]) -> dict[int, tuple[int, int]]:
    """Build symbol -> (canonical code, bit length) from code lengths."""

    maximum = max(lengths, default=0)
    counts = [0] * (maximum + 1)
    for length in lengths:
        if length:
            counts[length] += 1
    next_code = [0] * (maximum + 1)
    code = 0
    for length in range(1, maximum + 1):
        code = (code + counts[length - 1]) << 1
        next_code[length] = code
    result: dict[int, tuple[int, int]] = {}
    for symbol, length in enumerate(lengths):
        if length:
            result[symbol] = (next_code[length], length)
            next_code[length] += 1
    return result


def _write_encoded_length(writer: _BitWriter, length: int) -> None:
    if not 0 <= length <= 16:
        raise ValueError("LZH Huffman lengths must be between 0 and 16")
    writer.write(min(length, 7), 3)
    if length >= 7:
        for _ in range(length - 7):
            writer.write(1, 1)
        writer.write(0, 1)


def _write_auxiliary_tree(
    writer: _BitWriter,
    lengths: list[int],
    count_bits: int,
    special_zero_index: int | None,
) -> dict[int, tuple[int, int]]:
    """Write a PT-style tree and return its canonical code table."""

    active = [index for index, length in enumerate(lengths) if length]
    if not active:
        raise ValueError("an LZH auxiliary tree needs at least one symbol")
    if len(active) == 1:
        writer.write(0, count_bits)
        writer.write(active[0], count_bits)
        return {active[0]: (0, 0)}

    count = max(active) + 1
    if count >= 1 << count_bits:
        raise ValueError("LZH auxiliary tree is too large")
    writer.write(count, count_bits)
    index = 0
    while index < count:
        _write_encoded_length(writer, lengths[index])
        index += 1
        if special_zero_index is not None and index == special_zero_index:
            skipped = 0
            while index < 6 and lengths[index] == 0:
                index += 1
                skipped += 1
            writer.write(skipped, 2)
    return _canonical_codes(lengths)


def _write_main_tree(
    writer: _BitWriter,
    lengths: list[int],
    length_tree_codes: dict[int, tuple[int, int]],
) -> dict[int, tuple[int, int]]:
    """Write the C-table (main literal/match tree)."""

    active = [index for index, length in enumerate(lengths) if length]
    if not active:
        raise ValueError("an LZH main tree needs at least one symbol")
    if len(active) == 1:
        writer.write(0, 9)
        writer.write(active[0], 9)
        return {active[0]: (0, 0)}

    count = max(active) + 1
    if count >= 1 << 9:
        raise ValueError("LZH main tree is too large")
    writer.write(count, 9)
    constant_symbol = next(iter(length_tree_codes))

    def write_symbol(symbol: int) -> None:
        code, bits = length_tree_codes[symbol]
        if bits:
            writer.write(code, bits)
        elif symbol != constant_symbol:
            raise ValueError("invalid constant LZH length tree")

    index = 0
    while index < count:
        length = lengths[index]
        index += 1
        if length:
            write_symbol(length + 2)
            continue
        run = 1
        while index < count and lengths[index] == 0:
            index += 1
            run += 1
        if run <= 2:
            for _ in range(run):
                write_symbol(0)
        elif run <= 18:
            write_symbol(1)
            writer.write(run - 3, 4)
        elif run == 19:
            write_symbol(0)
            write_symbol(1)
            writer.write(15, 4)
        else:
            write_symbol(2)
            writer.write(run - 20, 9)
    return _canonical_codes(lengths)


def _tokenize_lzss(data: bytes, dictionary_bits: int) -> list[_LzhToken]:
    """Tokenize with the tree matcher selected by compatibility tests.

    This matcher reproduces the 4 KiB tag-0x63 streams in the compatibility
    corpus.
    It corresponds in structure to the percolating-update matcher of ar002
    encode.c (public domain) and may be adapted from it; see NOTICE.
    """

    if not data:
        return []

    dictionary_size = 1 << dictionary_bits
    dictionary_mask = dictionary_size - 1
    maximum_match = 256
    threshold = 3
    percolate_flag = 0x8000
    nil = 0
    maximum_hash = (
        3 * dictionary_size
        + (dictionary_size // 512 + 1) * 0xFF
    )

    text = bytearray(dictionary_size * 2 + maximum_match)
    level = [0] * (dictionary_size + 0x100)
    child_count = [0] * (dictionary_size + 0x100)
    position = [0] * (dictionary_size + 0x100)
    parent = [0] * (dictionary_size * 2)
    previous = [0] * (dictionary_size * 2)
    following = [0] * (maximum_hash + 1)

    for node in range(dictionary_size, dictionary_size + 0x100):
        level[node] = 1
    available = 1
    for node in range(1, dictionary_size - 1):
        following[node] = node + 1

    input_offset = min(len(data), dictionary_size + maximum_match)
    text[dictionary_size:dictionary_size + input_offset] = data[:input_offset]
    remainder = input_offset
    current = dictionary_size
    match_position = current
    match_length = 0

    def hash_index(node: int, byte: int) -> int:
        return (
            node
            + (byte << (dictionary_bits - 9))
            + dictionary_size * 2
        )

    def child(node: int, byte: int) -> int:
        candidate = following[hash_index(node, byte)]
        parent[nil] = node
        while parent[candidate] != node:
            candidate = following[candidate]
        return candidate

    def make_child(node: int, byte: int, new_child: int) -> None:
        slot = hash_index(node, byte)
        old_first = following[slot]
        following[slot] = new_child
        following[new_child] = old_first
        previous[old_first] = new_child
        previous[new_child] = slot
        parent[new_child] = node
        child_count[node] += 1

    def split(old: int) -> None:
        nonlocal available
        new = available
        available = following[new]
        child_count[new] = 0
        sibling = previous[old]
        previous[new] = sibling
        following[sibling] = new
        sibling = following[old]
        following[new] = sibling
        previous[sibling] = new
        parent[new] = parent[old]
        level[new] = match_length
        position[new] = current
        make_child(new, text[match_position + match_length], old)
        make_child(new, text[current + match_length], current)

    def insert_node() -> None:
        nonlocal match_length, match_position
        if match_length >= 4:
            match_length -= 1
            candidate = (match_position + 1) | dictionary_size
            ancestor = parent[candidate]
            while ancestor == nil:
                candidate = following[candidate]
                ancestor = parent[candidate]
            while level[ancestor] >= match_length:
                candidate = ancestor
                ancestor = parent[ancestor]

            updated = ancestor
            while position[updated] & percolate_flag:
                position[updated] = current
                updated = parent[updated]
            if updated < dictionary_size:
                position[updated] = current | percolate_flag
        else:
            ancestor = text[current] + dictionary_size
            candidate = child(ancestor, text[current + 1])
            if candidate == nil:
                make_child(ancestor, text[current + 1], current)
                match_length = 1
                return
            match_length = 2

        while True:
            if candidate >= dictionary_size:
                maximum = maximum_match
                match_position = candidate
            else:
                maximum = level[candidate]
                match_position = position[candidate] & ~percolate_flag
            if match_position >= current:
                match_position -= dictionary_size

            while match_length < maximum:
                if (
                    text[current + match_length]
                    != text[match_position + match_length]
                ):
                    split(candidate)
                    return
                match_length += 1

            if match_length >= maximum_match:
                break
            position[candidate] = current
            ancestor = candidate
            candidate = child(ancestor, text[current + match_length])
            if candidate == nil:
                make_child(ancestor, text[current + match_length], current)
                return
            match_length += 1

        sibling = previous[candidate]
        previous[current] = sibling
        following[sibling] = current
        sibling = following[candidate]
        following[current] = sibling
        previous[sibling] = current
        parent[current] = ancestor
        parent[candidate] = nil
        following[candidate] = current

    def delete_node() -> None:
        nonlocal available
        if parent[current] == nil:
            return
        left_sibling = previous[current]
        right_sibling = following[current]
        following[left_sibling] = right_sibling
        previous[right_sibling] = left_sibling
        removed_parent = parent[current]
        parent[current] = nil
        child_count[removed_parent] -= 1
        if removed_parent >= dictionary_size or child_count[removed_parent] > 1:
            return

        replacement_position = position[removed_parent] & ~percolate_flag
        if replacement_position >= current:
            replacement_position -= dictionary_size

        newest = replacement_position
        ancestor = parent[removed_parent]
        ancestor_position = position[ancestor]
        while ancestor_position & percolate_flag:
            candidate_position = ancestor_position & ~percolate_flag
            if candidate_position >= current:
                candidate_position -= dictionary_size
            newest = max(newest, candidate_position)
            position[ancestor] = newest | dictionary_size
            ancestor = parent[ancestor]
            ancestor_position = position[ancestor]
        if ancestor < dictionary_size:
            candidate_position = ancestor_position
            if candidate_position >= current:
                candidate_position -= dictionary_size
            newest = max(newest, candidate_position)
            position[ancestor] = (
                newest | dictionary_size | percolate_flag
            )

        replacement = child(
            removed_parent,
            text[replacement_position + level[removed_parent]],
        )
        left_sibling = previous[replacement]
        right_sibling = following[replacement]
        following[left_sibling] = right_sibling
        previous[right_sibling] = left_sibling
        left_sibling = previous[removed_parent]
        following[left_sibling] = replacement
        previous[replacement] = left_sibling
        right_sibling = following[removed_parent]
        previous[right_sibling] = replacement
        following[replacement] = right_sibling
        parent[replacement] = parent[removed_parent]
        parent[removed_parent] = nil
        following[removed_parent] = available
        available = removed_parent

    def get_next_match() -> None:
        nonlocal current, input_offset, remainder, text
        remainder -= 1
        current += 1
        if current == dictionary_size * 2:
            text[:dictionary_size + maximum_match] = text[
                dictionary_size:dictionary_size * 2 + maximum_match
            ]
            read_count = min(dictionary_size, len(data) - input_offset)
            start = dictionary_size + maximum_match
            text[start:start + read_count] = data[
                input_offset:input_offset + read_count
            ]
            input_offset += read_count
            remainder += read_count
            current = dictionary_size
        delete_node()
        insert_node()

    insert_node()
    match_length = min(match_length, remainder)
    tokens: list[_LzhToken] = []
    while remainder > 0:
        previous_length = match_length
        previous_position = match_position
        get_next_match()
        match_length = min(match_length, remainder)
        if match_length > previous_length or previous_length < threshold:
            tokens.append(_LzhToken(text[current - 1]))
            continue

        tokens.append(
            _LzhToken(
                previous_length + (256 - threshold),
                (current - previous_position - 2) & dictionary_mask,
            )
        )
        previous_length -= 1
        while previous_length > 0:
            get_next_match()
            previous_length -= 1
        match_length = min(match_length, remainder)

    return tokens


def _write_lzh_block(
    writer: _BitWriter,
    tokens: list[_LzhToken],
    dictionary_bits: int,
) -> None:
    writer.write(len(tokens), 16)
    main_frequencies = [0] * 510
    position_frequencies = [0] * (dictionary_bits + 1)
    for token in tokens:
        main_frequencies[token.symbol] += 1
        if token.symbol > 255:
            position_frequencies[token.distance.bit_length()] += 1

    main_lengths = _huffman_lengths(main_frequencies, require_verified=True)
    length_tree_frequencies = [0] * 19
    main_count = max(
        index for index, length in enumerate(main_lengths) if length
    ) + 1
    index = 0
    while index < main_count:
        length = main_lengths[index]
        index += 1
        if length:
            length_tree_frequencies[length + 2] += 1
            continue
        run = 1
        while index < main_count and main_lengths[index] == 0:
            index += 1
            run += 1
        if run <= 2:
            length_tree_frequencies[0] += run
        elif run <= 18:
            length_tree_frequencies[1] += 1
        elif run == 19:
            length_tree_frequencies[0] += 1
            length_tree_frequencies[1] += 1
        else:
            length_tree_frequencies[2] += 1
    length_lengths = _huffman_lengths(length_tree_frequencies, require_verified=True)
    length_codes = _write_auxiliary_tree(writer, length_lengths, 5, 3)
    main_codes = _write_main_tree(writer, main_lengths, length_codes)
    if not any(position_frequencies):
        # A literal-only block still carries a valid position tree, even though
        # the decoder never consults it.
        position_frequencies[0] = 1
    position_lengths = _huffman_lengths(position_frequencies, require_verified=True)
    position_codes = _write_auxiliary_tree(writer, position_lengths, 4, None)

    for token in tokens:
        code, bits = main_codes[token.symbol]
        writer.write(code, bits)
        if token.symbol > 255:
            position = token.distance.bit_length()
            code, bits = position_codes[position]
            writer.write(code, bits)
            if position:
                writer.write(token.distance - (1 << (position - 1)), position - 1)


def compress_lzh(data: bytes, *, dictionary_bits: int = 12) -> bytes:
    """Encode a raw LH4/LH5 static-Huffman stream using LZSS matches.

    Unlike :func:`compress_lzh_literals`, this encoder emits repeated metadata
    runs as length/distance pairs. The default 4 KiB dictionary and tree matcher
    reproduce the compressed tag-0x63 bytes of the supplied compatibility
    fixtures. The implementation uses only the Python standard library.
    """

    if dictionary_bits not in (12, 13):
        raise ValueError("dictionary_bits must be 12 or 13")
    if not data:
        writer = _BitWriter()
        writer.write(0, 16)
        return writer.finish()

    tokens = _tokenize_lzss(data, dictionary_bits)
    writer = _BitWriter()
    for offset in range(0, len(tokens), 0xFFFF):
        _write_lzh_block(writer, tokens[offset:offset + 0xFFFF], dictionary_bits)
    return writer.finish()
