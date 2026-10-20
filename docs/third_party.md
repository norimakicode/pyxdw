# Third-party origins

This page records where parts of pyxdw come from and what is still open.
The short user-facing summary is in [NOTICE](../NOTICE). This page is a
technical record, not legal advice.

The LZH *format* (LH4/LH5 static-Huffman blocks, LZSS matches) is a public,
widely documented format. Producing or reading compatible streams does not by
itself imply the use of any particular source code. The points below concern
source code, not the format.

## ar002 (Haruhiko Okumura)

### Public-domain statement

The author's distribution site states, in its `00README.txt`:

> ar002 -- written by Haruhiko Okumura and released to the public domain

### Source copies used for comparison

The copies below were retrieved on 2026-10-20 and compared with
`pyxdw/lzh.py`. They are not shipped with pyxdw.

| File | URL | SHA-256 |
|---|---|---|
| `00README.txt` | <https://okumuralab.org/~okumura/compression/ar002/00README.txt> | `0de1cf538b58b54644e29da299fee02916175ec7e2a5fb61eda637456f6dc7e2` |
| `encode.c` | <https://okumuralab.org/~okumura/compression/ar002/encode.c> | `303b61cba890b4ff5b29c1a5bb48f90d2adf09442399dbf3de0aafd64d47d1db` |
| `maketree.c` | <https://okumuralab.org/~okumura/compression/ar002/maketree.c> | `a198bca29e2eb02755fe33d648cb986c847136548be380670235ef77b2fd5504` |
| `huf.c` | <https://okumuralab.org/~okumura/compression/ar002/huf.c> | `da3b3997503cf68b20e1a00659c7bf23954cd15680f606533b10e24c8c4850a8` |
| `ar.h` | <https://okumuralab.org/~okumura/compression/ar002/ar.h> | `c8ffb15a53a3f6d095efafea3a5831a275c98f22f3cd5ca3ae660483fc499bb1` |

Files on the site can change. These hashes identify the 2026 copies. Whether
they are identical to what was consulted when the code was first written is
not known.

### Corresponding parts of `pyxdw/lzh.py`

| pyxdw | ar002 | Assessment |
|---|---|---|
| `_tokenize_lzss` | `encode.c` (percolating-update Patricia tree) | Close structural correspondence (node arrays, free list, hash sentinel, split, percolate and delete order). Probably adapted. |
| `_huffman_lengths`: heap, `downheap`, leaf order, length assignment | `maketree.c` | Same procedure; consistent with an adaptation. |
| `_write_auxiliary_tree`, `_write_main_tree`, `_write_lzh_block` | `huf.c` (`write_pt_len`, `write_c_len`, `count_t_freq`, `send_block`) | Partly required by the format, partly the same implementation choices (zero-run split, special index 3). |
| Decoder, bit reader/writer | `huf.c`, `decode.c` (by function only) | Different data structures (dictionary-based canonical decoding). No specific port identified. |

Python-side changes include token lists instead of packed buffers, explicit
flag checks instead of signed-short tricks, Python lists instead of fixed C
arrays, input validation, and removal of file, CRC and progress handling.

## Package-Merge (length-limited Huffman codes)

`_package_merge_lengths` is used only when the Huffman tree built as above
would exceed 16 bits.

- **Reference:** L. L. Larmore and D. S. Hirschberg, "A Fast Algorithm for
  Optimal Length-Limited Huffman Codes", *Journal of the ACM* 37(3), 1990,
  pp. 464–473, sections 2–3 ([author's copy](https://ics.uci.edu/~dhirschb/pubs/LenLimHuff.pdf)).
- **Design:** the simple O(nL) package DAG, not the linear-space variant.
  Ties prefer leaves over packages, then symbol order and package creation
  order.
- **Development:** written from the paper's problem statement. No code or text
  from the paper is reproduced. The developers had already compared other LZH
  implementations, so this is not a formal clean-room implementation.
- **Tests** (`tests/test_huffman.py`):
  - Kraft equality and prefix-freedom.
  - Cost compared with a separate dynamic-programming oracle on 216 small
    cases.
  - Over-deep Fibonacci frequencies.
  - Sparse and full 510-symbol alphabets.
  - Invalid inputs.
  - Unchanged streams for normal input, checked against pinned hashes.
- **Additional review:** a second review checked the function against
  exhaustive search, an independently written dynamic program and writer
  round trips that include matches. No discrepancies were found.

**Status:** the official DocuWorks API and Viewer have not yet been checked
with this output. Writers therefore raise `XdwUnsupportedFeatureError` when
the path would be needed.

## Iterative leaf-depth traversal

The former nested `count_leaves(node, depth)` recursion was replaced with an
explicit stack traversal. The replacement was designed from `_huffman_lengths`'
local tree representation and required result: count leaves at each depth and
detect any leaf beyond the configured limit. It was written without consulting
external implementations. Unlike the former function and LHa for UNIX's
similarly shaped `count_leaf`, it has no recursive leaf-counting function.

The existing tests cover empty and single-symbol alphabets, the depth-16
boundary, over-deep trees, full alphabets and fixed hashes of normal LZH output.
A focused test also checks the exact depths of two-leaf and balanced four-leaf
trees. This structural replacement does not establish that every copyright or
provenance question in the LZH codec is resolved.

## Open questions

These are **not resolved**.

1. **Original source consulted.** Which copy of ar002, or of a derivative,
   was used when `pyxdw/lzh.py` was first written was not recorded.
2. **Public-domain effect.** The legal effect of the public-domain statement
   in each jurisdiction has not been reviewed.
