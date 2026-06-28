import logging

from xsscane.core.evasion import AdaptiveEvader

LOG = logging.getLogger("t")


def test_block_detection():
    e = AdaptiveEvader(LOG)
    assert e.is_blocked(403, "") and e.is_blocked(429, "")
    assert e.is_blocked(200, "Request blocked by security policy")
    assert not e.is_blocked(200, "<h1>ok</h1>")


def test_variants_change_signature():
    e = AdaptiveEvader(LOG)
    variants = dict(e.variants("<script>alert(1)</script>"))
    assert "case" in variants and variants["case"] != "<script>alert(1)</script>"
    assert "double-url" in variants


def test_learn_promotes_winner():
    e = AdaptiveEvader(LOG)
    e.learn("html-entity")
    assert [name for name, _ in e.variants("x<y>")][0] == "html-entity"
    assert e.bypasses == 1 and e.preferred == "html-entity"


def test_waf_seed_orders_preference():
    e = AdaptiveEvader(LOG, waf_name="ModSecurity")
    assert [name for name, _ in e.variants("x<y>")][0] == "html-entity"
