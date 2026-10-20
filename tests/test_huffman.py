"""Length-limited Huffman checks using synthetic data and an independent DP.

The slot DP is an optimal-cost oracle, not another Package-Merge implementation.
No XDW files, official SDK, or LHa reference implementation are used here.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
import random
import unittest
from unittest.mock import patch

from pyxdw import XdwUnsupportedFeatureError
from pyxdw import lzh


def fibonacci_frequencies(count):
    weights = [1, 1]
    while len(weights) < count:
        weights.append(weights[-2] + weights[-1])
    return weights[:count]


def optimal_cost(frequencies, limit):
    """Enumerate full-tree layer sizes, assigning heavy leaves first."""
    weights = sorted((w for w in frequencies if w), reverse=True)
    prefix = [0]
    for weight in weights:
        prefix.append(prefix[-1] + weight)
    count = len(weights)

    @lru_cache(None)
    def solve(depth, assigned, slots):
        if assigned == count:
            return 0 if slots == 0 else float("inf")
        if depth > limit or slots == 0 or slots > count - assigned:
            return float("inf")
        best = float("inf")
        for leaves in range(min(slots, count - assigned) + 1):
            used = assigned + leaves
            cost = depth * (prefix[used] - prefix[assigned])
            best = min(best, cost + solve(depth + 1, used, 2 * (slots - leaves)))
        return best

    return solve(1, 0, 2)


class HuffmanTest(unittest.TestCase):
    def assert_prefix_code(self, frequencies, lengths, limit):
        self.assertEqual(len(frequencies), len(lengths))
        for weight, length in zip(frequencies, lengths):
            self.assertEqual(weight > 0, length > 0)
            self.assertLessEqual(length, limit)
        capacity = sum(1 << (limit - length) for length in lengths if length)
        self.assertLessEqual(capacity, 1 << limit)
        if sum(weight > 0 for weight in frequencies) > 1:
            self.assertEqual(capacity, 1 << limit)
        words = [format(code, f"0{width}b")
                 for code, width in lzh._canonical_codes(lengths).values()]
        for i, word in enumerate(words):
            for j, other in enumerate(words):
                if i != j:
                    self.assertFalse(other.startswith(word))

    def test_overdeep_tree_routes_to_package_merge(self):
        # Before replacement these 6764 observations triggered overflow=1.
        frequencies = fibonacci_frequencies(18) + [0] * (510 - 18)
        with patch.object(lzh, "_package_merge_lengths",
                          wraps=lzh._package_merge_lengths) as merge:
            lengths = lzh._huffman_lengths(frequencies)
        merge.assert_called_once_with(frequencies, 16)
        self.assertEqual(sum(frequencies), 6764)
        self.assertEqual(max(lengths), 16)
        self.assert_prefix_code(frequencies, lengths, 16)
        self.assertEqual(sum(w * n for w, n in zip(frequencies, lengths)),
                         optimal_cost(frequencies, 16))

    def test_depth_sixteen_boundary_keeps_existing_path(self):
        frequencies = fibonacci_frequencies(17)
        with patch.object(lzh, "_package_merge_lengths",
                          side_effect=AssertionError("unnecessary replacement")):
            lengths = lzh._huffman_lengths(frequencies)
        self.assertEqual(max(lengths), 16)
        self.assert_prefix_code(frequencies, lengths, 16)

    def test_shallow_leaf_depths(self):
        for frequencies, expected in (([1, 1], [1, 1]),
                                      ([1, 1, 1, 1], [2, 2, 2, 2])):
            with self.subTest(frequencies=frequencies):
                with patch.object(lzh, "_package_merge_lengths",
                                  side_effect=AssertionError("unnecessary replacement")):
                    self.assertEqual(lzh._huffman_lengths(frequencies), expected)

    def test_package_merge_matches_independent_optimal_cost(self):
        generator = random.Random(42)
        for limit in range(1, 5):
            for count in range(2, min(8, 1 << limit) + 1):
                cases = [[1] * count, list(range(1, count + 1))]
                cases += [[generator.randrange(1, 100) for _ in range(count)]
                          for _ in range(10)]
                for weights in cases:
                    with self.subTest(limit=limit, weights=weights):
                        lengths = lzh._package_merge_lengths(weights, limit)
                        self.assert_prefix_code(weights, lengths, limit)
                        self.assertEqual(sum(w * n for w, n in zip(weights, lengths)),
                                         optimal_cost(weights, limit))

    def test_sparse_and_equal_weights_are_deterministic(self):
        for weights in ([0, 3, 0, 3, 3, 0, 3], [1] * 510):
            first = lzh._package_merge_lengths(weights, 16)
            for _ in range(3):
                self.assertEqual(lzh._package_merge_lengths(weights, 16), first)
            self.assert_prefix_code(weights, first, 16)

    def test_full_alphabet_and_extreme_skew(self):
        for weights in (fibonacci_frequencies(510),
                        [1] * 509 + [10**100]):
            lengths = lzh._huffman_lengths(weights)
            self.assert_prefix_code(weights, lengths, 16)

    def test_zero_and_single_symbol(self):
        for function in (lzh._huffman_lengths, lzh._package_merge_lengths):
            for weights in ([], [0] * 19, [0, 5, 0]):
                lengths = function(weights, 16)
                self.assertEqual(lengths, [int(w > 0) for w in weights])
                self.assert_prefix_code(weights, lengths, 16)

    def test_invalid_or_infeasible_inputs(self):
        for function in (lzh._huffman_lengths, lzh._package_merge_lengths):
            for weights, limit in (([1, -1], 16), ([1.5, 2], 16),
                                   ([1, 2], 0), ([1, 2], 17),
                                   ([1, 1, 1], 1)):
                with self.subTest(function=function.__name__, weights=weights, limit=limit):
                    with self.assertRaises(ValueError):
                        function(weights, limit)

    def test_overflow_writes_require_official_verification(self):
        weights = fibonacci_frequencies(18)
        with self.assertRaisesRegex(XdwUnsupportedFeatureError, "not yet verified"):
            lzh._huffman_lengths(weights, require_verified=True)
        tokens = [lzh._LzhToken(i) for i, weight in enumerate(weights)
                  for _ in range(weight)]
        with self.assertRaises(XdwUnsupportedFeatureError):
            lzh._write_lzh_block(lzh._BitWriter(), tokens, 12)
        with patch.object(lzh, "_tokenize_lzss", return_value=tokens):
            with self.assertRaises(XdwUnsupportedFeatureError):
                lzh.compress_lzh(b"synthetic token source")

    def test_experimental_overflow_blocks_round_trip(self):
        # Test-only bypass of the writer's verification gate, never a public flag.
        construct = lzh._huffman_lengths
        for count in (18, 22):
            weights = fibonacci_frequencies(count)
            tokens = [lzh._LzhToken(i) for i, weight in enumerate(weights)
                      for _ in range(weight)]
            expected = bytes(token.symbol for token in tokens)
            for bits in (12, 13):
                with self.subTest(count=count, dictionary_bits=bits):
                    writer = lzh._BitWriter()
                    with patch.object(lzh, "_huffman_lengths",
                                      side_effect=lambda f, **kw: construct(f)):
                        lzh._write_lzh_block(writer, tokens, bits)
                    self.assertEqual(lzh.decompress_lzh(writer.finish(), len(expected),
                                                       dictionary_bits=bits), expected)

    def test_normal_streams_match_before_replacement(self):
        generator = random.Random(20261020)
        samples = [b"", b"a", b"abcde" * 3276, bytes(range(256)) * 64,
                   generator.randbytes(16384)]
        # SHA-256 of pre-change streams, not third-party compressed data.
        common = ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                  "d88b8d72447d283f628a3b5ce3e1983a7c07005285c1c3f94f10559befc7a332",
                  "eff21ae8e2c563ac34b57cb3f94e8b35c532559f16cf169d34db4d307b52fa4a",
                  "3a508d53be506326f3ab0058de6a3084590fda8e774567dca7fb1b3b2e99b2a8"]
        for bits, last in ((12, "3cb5e9e9ddf624036ab70ad2da40a638cb12f09abbc1e5117cbfc250af01a57f"),
                           (13, "df18f3df54f9dda6fb18ce36d9e6885eb295c50640991eac7d1c6ed8b4380c5e")):
            for data, digest in zip(samples, common + [last]):
                encoded = lzh.compress_lzh(data, dictionary_bits=bits)
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)
                self.assertEqual(lzh.decompress_lzh(encoded, len(data),
                                                   dictionary_bits=bits), data)


if __name__ == "__main__":
    unittest.main()
