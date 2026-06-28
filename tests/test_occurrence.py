from dataclasses import dataclass

from xsscane.payloads import occurrence as occ


@dataclass
class P:
    decoded: str


def test_survival_marker():
    assert occ.survival_marker("TOK") == "TOK<>\"'`/;TOK"


def test_surviving_chars_strips_angles():
    body = "<script>var a='TOK\"'`/;TOK';</script>"
    surviving = occ.surviving_chars(body, "TOK")
    assert "<" not in surviving and ">" not in surviving
    assert {"'", '"', ";", "/"}.issubset(surviving)


def test_select_filters_and_ranks():
    surviving = {"'", '"', ";", "/"}
    payloads = [
        P("</script><svg onload=alert('c')>"),  # needs < > -> impossible
        P("';alert('c');//"),
        P("\";alert('c');//"),
    ]
    viable = occ.select(payloads, surviving)
    assert len(viable) == 2 and all("<" not in p.decoded for p in viable)


def test_select_without_signal_keeps_all():
    payloads = [P("<x>"), P("y")]
    assert len(occ.select(payloads, set())) == 2
