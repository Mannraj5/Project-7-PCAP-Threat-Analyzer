import json

from pcapscope import craft
from pcapscope.cli import main


def _scan_capture(path):
    frames = [(1000.0 + p / 1000, craft.syn_frame("10.0.0.66", "10.0.0.20", 50000, p)) for p in range(1, 101)]
    craft.write_pcap(path, frames)


def test_cli_writes_markdown_and_json(tmp_path, capsys):
    capture = tmp_path / "scan.pcap"
    _scan_capture(capture)
    md, js = tmp_path / "out" / "r.md", tmp_path / "out" / "r.json"

    assert main([str(capture), "--report", str(md), "--json", str(js)]) == 0

    assert "TCP port scan of 10.0.0.20" in capsys.readouterr().out
    text = md.read_text(encoding="utf-8")
    assert "# pcapscope report - `scan.pcap`" in text
    assert "Ports probed:** 100" in text
    doc = json.loads(js.read_text(encoding="utf-8"))
    assert doc["summary"]["packets"] == 100
    assert doc["findings"][0]["rule"] == "port-scan"


def test_cli_fail_on_threshold(tmp_path):
    capture = tmp_path / "scan.pcap"
    _scan_capture(capture)
    assert main([str(capture), "--fail-on", "medium"]) == 2
    assert main([str(capture), "--fail-on", "high"]) == 0


def test_cli_thresholds_are_configurable(tmp_path, capsys):
    capture = tmp_path / "scan.pcap"
    _scan_capture(capture)
    main([str(capture), "--scan-ports", "500"])
    assert "no findings" in capsys.readouterr().out


def test_cli_multiple_captures_write_into_directory(tmp_path):
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    _scan_capture(a)
    _scan_capture(b)
    assert main([str(a), str(b), "--report", str(tmp_path / "reports")]) == 0
    assert sorted(p.name for p in (tmp_path / "reports").iterdir()) == ["a.md", "b.md"]


def test_cli_reports_bad_input(tmp_path, capsys):
    junk = tmp_path / "junk.pcap"
    junk.write_text("nope")
    assert main([str(junk)]) == 1
    assert "unrecognised magic" in capsys.readouterr().err
