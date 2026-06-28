import logging

from xsscane.core.config import ScanConfig
from xsscane.modules.fuzzer import AsyncFuzzer, Context
from xsscane.payloads.generator import PolymorphicPayloadGenerator

GEN = PolymorphicPayloadGenerator()
FUZZER = AsyncFuzzer(ScanConfig(url="http://t/"), None, GEN, logging.getLogger("t"))


def test_base_payload_count():
    assert len(GEN.base_payloads()) == 13


def test_uri_payloads_do_not_prefix_original():
    payloads = GEN.context_payloads("uri", "http://orig/", '"')
    assert all(p.value == p.decoded for p in payloads)
    assert any(p.value.startswith("javascript:") for p in payloads)
    assert any(p.value.startswith("data:text/html") for p in payloads)


def test_mutate_preserves_canary():
    base = GEN.base_payloads()[0]
    for variant in GEN.mutate(base):
        assert variant.canary == base.canary and variant.decoded == base.decoded


def test_context_detection():
    assert FUZZER._classify('<input value="CAN">', "CAN") == {(Context.ATTRIBUTE, '"')}
    assert FUZZER._classify("<p>CAN</p>", "CAN") == {(Context.HTML, "")}
    assert FUZZER._classify("<script>var a='CAN'", "CAN") == {(Context.SCRIPT, "")}
    href = FUZZER._classify('<a href="x CAN">', "CAN")
    assert (Context.URI, '"') in href and (Context.ATTRIBUTE, '"') in href
