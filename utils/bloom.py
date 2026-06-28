from __future__ import annotations

import hashlib
import math


class BloomFilter:
    """Space-efficient probabilistic set for URL de-duplication on large link
    graphs. Membership tests never yield false negatives; the configured error
    rate bounds false positives (a URL wrongly treated as already-seen)."""

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001):
        self.capacity = max(1, capacity)
        self.error_rate = error_rate
        self.size = self._optimal_size(self.capacity, error_rate)
        self.hash_count = self._optimal_hashes(self.size, self.capacity)
        self._bits = bytearray((self.size + 7) // 8)
        self.count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        return max(8, int(-(n * math.log(p)) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_hashes(m: int, n: int) -> int:
        return max(1, int((m / n) * math.log(2)))

    def _indexes(self, item: str):
        # Double hashing (Kirsch-Mitzenmacher): derive k indexes from two base
        # digests, avoiding the cost of k independent hash functions.
        data = item.encode("utf-8", "ignore")
        h1 = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")
        h2 = int.from_bytes(hashlib.blake2b(data, digest_size=8, salt=b"bloom").digest(), "big") | 1
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def add(self, item: str) -> bool:
        """Insert an item; return True if it was (probably) already present."""
        already_present = True
        for index in self._indexes(item):
            byte, bit = divmod(index, 8)
            mask = 1 << bit
            if not self._bits[byte] & mask:
                already_present = False
                self._bits[byte] |= mask
        if not already_present:
            self.count += 1
        return already_present

    def __contains__(self, item: str) -> bool:
        return all(self._bits[i // 8] & (1 << (i % 8)) for i in self._indexes(item))

    def __len__(self) -> int:
        return self.count
