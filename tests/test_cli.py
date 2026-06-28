import json

import pytest

from xsscane import cli


def test_config_file_supplies_defaults(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"url": "http://fromfile/", "evasion": 1, "concurrency": 7}))
    args = cli.parse_args(["--config", str(cfg)])
    assert args.url == "http://fromfile/" and args.evasion == 1 and args.concurrency == 7


def test_cli_flags_override_config(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"url": "http://fromfile/", "evasion": 1}))
    args = cli.parse_args(["--config", str(cfg), "--evasion", "3", "-u", "http://cli/"])
    assert args.evasion == 3 and args.url == "http://cli/"


def test_missing_url_errors():
    with pytest.raises(SystemExit):
        cli.parse_args([])


def test_oast_url_enables_blind():
    args = cli.parse_args(["-u", "http://t/", "--oast-url", "http://h:8888"])
    config = cli.build_config(args)
    assert "blind" in config.scan_types
