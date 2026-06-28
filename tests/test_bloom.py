from xsscane.utils.bloom import BloomFilter


def test_no_false_negatives():
    bf = BloomFilter(capacity=5000, error_rate=0.001)
    items = [f"http://t/{i}" for i in range(2000)]
    for item in items:
        bf.add(item)
    assert all(item in bf for item in items)


def test_add_reports_prior_presence():
    bf = BloomFilter(capacity=1000)
    assert bf.add("x") is False
    assert bf.add("x") is True


def test_false_positive_rate_is_low():
    bf = BloomFilter(capacity=5000, error_rate=0.001)
    for i in range(2000):
        bf.add(f"http://t/{i}")
    false_positives = sum(1 for i in range(5000, 10000) if f"http://t/{i}" in bf)
    assert false_positives / 5000 < 0.02
