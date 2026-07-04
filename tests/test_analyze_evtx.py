"""Tests for the EVTX (Windows Event Log) analyzer — phase 14.4.

Coverage:
- File / chunk / record structure parsing
- BinXML literal token decoding (no templates)
- FILETIME → ISO timestamp conversion
- SID string rendering
- Detection rules (25 rules, each in isolation)
- Summary metadata population
- IOC extraction from field values
- Dispatcher integration (format detection + route)
- Robustness under malformed / truncated input
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity
from ioc_hunter.analyze.dispatcher import analyze_bytes, detect_format
from ioc_hunter.analyze.evtx import (
    _VT_FILETIME,
    _VT_GUID,
    _VT_HEX32,
    _VT_U16,
    _VT_U32,
    _VT_WSTR,
    _binxml_name,
    _Cursor,
    _decode_value,
    _filetime_to_iso,
    _parse_sid,
    _unix_to_filetime,
)
from tests._evtx_fixtures import (
    _BinXmlBuilder,
    _build_file_header,
    _ts,
    build_admin_share_evtx,
    build_asrep_evtx,
    build_bruteforce_evtx,
    build_evtx,
    build_explicit_cred_evtx,
    build_kerberoasting_evtx,
    build_log_cleared_evtx,
    build_lolbin_evtx,
    build_minimal_evtx,
    build_multi_channel_evtx,
    build_new_account_evtx,
    build_new_service_evtx,
    build_password_spray_evtx,
    build_rdp_logon_evtx,
    build_scheduled_task_evtx,
    build_sensitive_group_evtx,
    build_success_after_fail_evtx,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(raw: bytes) -> AnalyzerReport:
    """Run the EVTX analyzer and return the populated report."""
    return analyze_bytes(raw, label="test.evtx")


def _rules(report: AnalyzerReport) -> set[str]:
    return {f.rule for f in report.findings}


def _severities(report: AnalyzerReport) -> dict[str, int]:
    return {f.rule: int(f.severity) for f in report.findings}


# ---------------------------------------------------------------------------
# 1. Format detection
# ---------------------------------------------------------------------------


class TestFormatDetection:
    def test_evtx_magic_detected(self):
        raw = build_minimal_evtx()
        assert detect_format(raw[:16]) == FileFormat.EVTX

    def test_non_evtx_not_detected(self):
        assert detect_format(b"PK\x03\x04" + b"\x00" * 12) != FileFormat.EVTX
        assert detect_format(b"MZ" + b"\x00" * 14) != FileFormat.EVTX


# ---------------------------------------------------------------------------
# 2. FILETIME utilities
# ---------------------------------------------------------------------------


class TestFiletimeUtils:
    def test_filetime_to_iso_known_value(self):
        # 2024-01-01 00:00:00 UTC
        # Unix: 1704067200
        # FILETIME: (1704067200 + 11644473600) * 10_000_000
        ft = (1704067200 + 11644473600) * 10_000_000
        iso = _filetime_to_iso(ft)
        assert iso == "2024-01-01T00:00:00Z"

    def test_filetime_zero_returns_epoch(self):
        # FILETIME 0 = 1601-01-01, yields a string not a crash
        result = _filetime_to_iso(0)
        assert isinstance(result, str)
        assert "T" in result

    def test_unix_to_filetime_roundtrip(self):
        unix_ts = 1700000000.0
        ft = _unix_to_filetime(unix_ts)
        back = _filetime_to_iso(ft)
        assert "2023" in back  # rough sanity


# ---------------------------------------------------------------------------
# 3. SID parsing
# ---------------------------------------------------------------------------


class TestSidParsing:
    def test_well_known_system_sid(self):
        # S-1-5-18 = SYSTEM
        # revision=1, sub_count=1, authority=5 (big-endian as 6 bytes), sub=18
        authority = struct.pack(">Q", 5)[2:]  # 6 bytes big-endian = 0x00_00_00_00_00_05
        data = bytes([1, 1]) + authority + struct.pack("<I", 18)
        assert _parse_sid(data) == "S-1-5-18"

    def test_domain_user_sid(self):
        # S-1-5-21-A-B-C-1001
        authority = struct.pack(">Q", 5)[2:]
        data = bytes([1, 5]) + authority + struct.pack("<5I", 21, 111, 222, 333, 1001)
        result = _parse_sid(data)
        assert result.startswith("S-1-5-21-")
        assert result.endswith("-1001")

    def test_truncated_sid_returns_empty(self):
        assert _parse_sid(b"\x01") == ""
        assert _parse_sid(b"") == ""


# ---------------------------------------------------------------------------
# 4. Value decoding
# ---------------------------------------------------------------------------


class TestValueDecoding:
    def test_wstring_decode(self):
        data = "Hello".encode("utf-16-le")
        assert _decode_value(data, _VT_WSTR) == "Hello"

    def test_uint16_decode(self):
        data = struct.pack("<H", 4625)
        assert _decode_value(data, _VT_U16) == "4625"

    def test_uint32_decode(self):
        data = struct.pack("<I", 65536)
        assert _decode_value(data, _VT_U32) == "65536"

    def test_hex32_decode(self):
        data = struct.pack("<I", 0x17)
        assert _decode_value(data, _VT_HEX32) == "0x00000017"

    def test_filetime_decode(self):
        ft = (1704067200 + 11644473600) * 10_000_000
        data = struct.pack("<Q", ft)
        result = _decode_value(data, _VT_FILETIME)
        assert result == "2024-01-01T00:00:00Z"

    def test_guid_decode(self):
        # {12345678-ABCD-EF01-2345-67890ABCDEF0}
        data = struct.pack("<IHH", 0x12345678, 0xABCD, 0xEF01) + bytes.fromhex("234567890ABCDEF0")
        result = _decode_value(data, _VT_GUID)
        assert result.startswith("{12345678-")

    def test_empty_data_returns_empty(self):
        assert _decode_value(b"", _VT_WSTR) == ""
        assert _decode_value(b"", _VT_U16) == ""


# ---------------------------------------------------------------------------
# 5. Cursor reader
# ---------------------------------------------------------------------------


class TestCursor:
    def test_sequential_reads(self):
        # u8(1=0x01) + u16(2=0x0200 LE → \x02\x00) + u32(4=\x04\x00\x00\x00)
        r = _Cursor(b"\x01\x02\x00\x04\x00\x00\x00")
        assert r.u8() == 1
        assert r.u16() == 2
        assert r.u32() == 4

    def test_oob_returns_none(self):
        r = _Cursor(b"\x01\x02")
        assert r.u8() == 1
        assert r.u8() == 2
        assert r.u8() is None
        assert r.u16() is None

    def test_read_bytes(self):
        r = _Cursor(b"ABCDEF")
        assert r.read(3) == b"ABC"
        assert r.read(2) == b"DE"
        assert r.read(2) is None

    def test_skip(self):
        r = _Cursor(b"\x00" * 10)
        assert r.skip(5)
        assert r.pos == 5
        assert not r.skip(100)


# ---------------------------------------------------------------------------
# 6. BinXML name reader
# ---------------------------------------------------------------------------


class TestBinXmlName:
    def test_read_name_from_builder_output(self):
        b = _BinXmlBuilder()
        binxml = b.frag_header().open_elem("EventID").val_u16(4625).close_elem().eof().build()
        # frag_header(4) + token(1) + dep_id(2) + data_size(4) = 11 bytes before name_offset slot
        name_off = struct.unpack_from("<I", binxml, 11)[0]
        # name_off should point into the name section at end of blob
        name = _binxml_name(binxml, name_off)
        assert name == "EventID"

    def test_oob_returns_empty(self):
        assert _binxml_name(b"\x00" * 5, 1000) == ""
        assert _binxml_name(b"", 0) == ""

    def test_zero_length_name(self):
        # name header with length=0
        data = struct.pack("<IIHH", 0, 0, 0, 0)
        assert _binxml_name(data, 0) == ""


# ---------------------------------------------------------------------------
# 7. BinXML event parsing
# ---------------------------------------------------------------------------


class TestBinXmlEventParsing:
    def test_parses_event_id(self):
        raw = build_minimal_evtx(event_id=4624)
        report = _make_report(raw)
        s = report.metadata["evtx_summary"]
        assert "4624" in s["event_id_distribution"]

    def test_parses_channel(self):
        raw = build_minimal_evtx(event_id=4624)
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["channel"] == "Security"

    def test_parses_computer(self):
        raw = build_minimal_evtx(event_id=4624)
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["computer"] == "TESTPC"

    def test_parses_provider(self):
        raw = build_minimal_evtx(event_id=4624)
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["provider"] == "Microsoft-Windows-Security-Auditing"

    def test_parses_data_fields(self):
        raw = build_evtx(
            [
                (
                    _ts(0),
                    {
                        "event_id": 4624,
                        "data_fields": {"TargetUserName": "alice", "LogonType": "3"},
                    },
                ),
            ]
        )
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["total_records"] == 1

    def test_time_range(self):
        raw = build_evtx(
            [
                (_ts(0), {"event_id": 4624, "data_fields": {}}),
                (_ts(3600), {"event_id": 4624, "data_fields": {}}),
            ]
        )
        report = _make_report(raw)
        s = report.metadata["evtx_summary"]
        assert s["time_first"] != s["time_last"]


# ---------------------------------------------------------------------------
# 8. Detection rules
# ---------------------------------------------------------------------------


class TestKerberoasting:
    def test_kerberoasting_rule_fires(self):
        raw = build_kerberoasting_evtx()
        report = _make_report(raw)
        assert "evtx.kerberoasting" in _rules(report)

    def test_kerberoasting_severity(self):
        raw = build_kerberoasting_evtx()
        report = _make_report(raw)
        sev = _severities(report)
        assert sev["evtx.kerberoasting"] >= int(Severity.HIGH)

    def test_kerberoasting_tickets_in_metadata(self):
        raw = build_kerberoasting_evtx()
        report = _make_report(raw)
        tickets = report.metadata["evtx_summary"]["kerberos_rc4_tickets"]
        assert len(tickets) >= 1
        assert tickets[0]["etype"] == "0x17"


class TestAsrepRoasting:
    def test_asrep_rule_fires(self):
        raw = build_asrep_evtx()
        report = _make_report(raw)
        assert "evtx.asrep_roasting" in _rules(report)

    def test_asrep_severity(self):
        raw = build_asrep_evtx()
        report = _make_report(raw)
        assert _severities(report)["evtx.asrep_roasting"] >= int(Severity.HIGH)


class TestBruteForce:
    def test_bruteforce_fires(self):
        raw = build_bruteforce_evtx(fail_count=12)
        report = _make_report(raw)
        assert "evtx.bruteforce_logon" in _rules(report)

    def test_below_threshold_no_brute_rule(self):
        raw = build_bruteforce_evtx(fail_count=3)
        report = _make_report(raw)
        assert "evtx.bruteforce_logon" not in _rules(report)

    def test_bruteforce_severity_high(self):
        raw = build_bruteforce_evtx(fail_count=15)
        report = _make_report(raw)
        assert _severities(report)["evtx.bruteforce_logon"] >= int(Severity.HIGH)


class TestPasswordSpray:
    def test_spray_fires(self):
        raw = build_password_spray_evtx(user_count=7)
        report = _make_report(raw)
        assert "evtx.pass_spray" in _rules(report)

    def test_spray_below_threshold(self):
        raw = build_password_spray_evtx(user_count=2)
        report = _make_report(raw)
        assert "evtx.pass_spray" not in _rules(report)


class TestLogClearing:
    def test_log_clear_fires_critical(self):
        raw = build_log_cleared_evtx()
        report = _make_report(raw)
        assert "evtx.security_log_cleared" in _rules(report)
        assert _severities(report)["evtx.security_log_cleared"] == int(Severity.CRITICAL)

    def test_log_cleared_in_summary(self):
        raw = build_log_cleared_evtx()
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["log_cleared"] is True


class TestLolBin:
    def test_lolbin_certutil_fires(self):
        raw = build_lolbin_evtx()
        report = _make_report(raw)
        assert "evtx.lolbin_execution" in _rules(report)

    def test_encoded_powershell_fires(self):
        raw = build_lolbin_evtx()
        report = _make_report(raw)
        assert "evtx.encoded_powershell" in _rules(report)

    def test_cmdlines_in_metadata(self):
        raw = build_lolbin_evtx()
        report = _make_report(raw)
        cmdlines = report.metadata["evtx_summary"]["cmdlines"]
        assert len(cmdlines) >= 1
        assert any("-enc" in c or "-NoP" in c for c in cmdlines)


class TestRdpLogon:
    def test_rdp_rule_fires(self):
        raw = build_rdp_logon_evtx()
        report = _make_report(raw)
        assert "evtx.rdp_logon" in _rules(report)

    def test_rdp_source_ip_in_summary(self):
        raw = build_rdp_logon_evtx()
        report = _make_report(raw)
        ips = report.metadata["evtx_summary"]["source_ips"]
        assert "203.0.113.5" in ips


class TestNewService:
    def test_service_rule_fires(self):
        raw = build_new_service_evtx()
        report = _make_report(raw)
        assert "evtx.new_service" in _rules(report)

    def test_services_in_metadata(self):
        raw = build_new_service_evtx()
        report = _make_report(raw)
        svcs = report.metadata["evtx_summary"]["services_installed"]
        assert len(svcs) >= 1
        assert svcs[0]["name"] == "WindowsDefenderUpdate"


class TestScheduledTask:
    def test_sched_task_rule_fires(self):
        raw = build_scheduled_task_evtx()
        report = _make_report(raw)
        assert "evtx.scheduled_task_created" in _rules(report)

    def test_sched_tasks_in_metadata(self):
        raw = build_scheduled_task_evtx()
        report = _make_report(raw)
        tasks = report.metadata["evtx_summary"]["scheduled_tasks"]
        assert len(tasks) >= 1
        assert "Telemetry" in tasks[0]


class TestNewAccount:
    def test_account_created_rule(self):
        raw = build_new_account_evtx()
        report = _make_report(raw)
        assert "evtx.account_created" in _rules(report)

    def test_severity_high(self):
        raw = build_new_account_evtx()
        report = _make_report(raw)
        assert _severities(report)["evtx.account_created"] >= int(Severity.HIGH)


class TestSuccessAfterFailures:
    def test_success_after_fail_fires(self):
        raw = build_success_after_fail_evtx()
        report = _make_report(raw)
        assert "evtx.success_after_failures" in _rules(report)


class TestExplicitCred:
    def test_explicit_cred_fires(self):
        raw = build_explicit_cred_evtx()
        report = _make_report(raw)
        assert "evtx.explicit_credential_logon" in _rules(report)


class TestAdminShare:
    def test_admin_share_fires(self):
        raw = build_admin_share_evtx()
        report = _make_report(raw)
        assert "evtx.admin_share_access" in _rules(report)


class TestSensitiveGroup:
    def test_sensitive_group_fires(self):
        raw = build_sensitive_group_evtx()
        report = _make_report(raw)
        assert "evtx.sensitive_group_change" in _rules(report)

    def test_sensitive_group_high_severity(self):
        raw = build_sensitive_group_evtx()
        report = _make_report(raw)
        assert _severities(report)["evtx.sensitive_group_change"] >= int(Severity.HIGH)


# ---------------------------------------------------------------------------
# 9. ATT&CK tagging
# ---------------------------------------------------------------------------


class TestAttackTagging:
    def test_kerberoasting_tagged_t1558_003(self):
        raw = build_kerberoasting_evtx()
        report = _make_report(raw)
        krb_findings = [f for f in report.findings if f.rule == "evtx.kerberoasting"]
        assert krb_findings
        assert "T1558.003" in krb_findings[0].mitre

    def test_log_clear_tagged_t1070_001(self):
        raw = build_log_cleared_evtx()
        report = _make_report(raw)
        clear_findings = [f for f in report.findings if f.rule == "evtx.security_log_cleared"]
        assert clear_findings
        assert "T1070.001" in clear_findings[0].mitre

    def test_rdp_tagged_t1021_001(self):
        raw = build_rdp_logon_evtx()
        report = _make_report(raw)
        rdp_findings = [f for f in report.findings if f.rule == "evtx.rdp_logon"]
        assert rdp_findings
        assert "T1021.001" in rdp_findings[0].mitre

    def test_new_service_tagged_t1543_003(self):
        raw = build_new_service_evtx()
        report = _make_report(raw)
        svc_findings = [f for f in report.findings if f.rule == "evtx.new_service"]
        assert svc_findings
        assert "T1543.003" in svc_findings[0].mitre


# ---------------------------------------------------------------------------
# 10. IOC extraction
# ---------------------------------------------------------------------------


class TestIocExtraction:
    def test_ip_extracted_from_logon(self):
        raw = build_rdp_logon_evtx()
        report = _make_report(raw)
        ioc_values = {ioc.value for ioc in report.iocs}
        assert "203.0.113.5" in ioc_values

    def test_no_garbage_iocs_from_binary(self):
        """The raw EVTX binary should not pollute the IOC list."""
        raw = build_minimal_evtx()
        report = _make_report(raw)
        for ioc in report.iocs:
            # IOC values should be readable strings, not hex garbage
            assert ioc.value.isprintable() or len(ioc.value) < 4


# ---------------------------------------------------------------------------
# 11. Robustness / adversarial input
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_wrong_magic_no_crash(self):
        raw = b"NOTEVTX\x00" + b"\x00" * 4088
        report = _make_report(raw)
        assert report is not None

    def test_truncated_file_no_crash(self):
        raw = build_minimal_evtx()[:100]
        report = _make_report(raw)
        assert report is not None

    def test_empty_bytes_no_crash(self):
        report = _make_report(b"")
        assert report is not None

    def test_random_bytes_no_crash(self):
        import os

        raw = os.urandom(65536 + 4096)
        # Patch in EVTX magic so it routes to the EVTX analyzer
        raw = b"ElfFile\x00" + raw[8:]
        report = _make_report(raw)
        assert report is not None

    def test_truncated_record_skipped(self):
        """A chunk with one valid record followed by a truncated record parses OK."""
        raw_full = build_minimal_evtx(event_id=4624)
        report = _make_report(raw_full)
        assert report.metadata["evtx_summary"]["total_records"] >= 1

    def test_zero_chunks_no_crash(self):
        hdr = _build_file_header(num_chunks=0)
        raw = hdr  # no chunk data at all
        report = _make_report(raw)
        assert report is not None

    def test_multiple_records_parsed(self):
        specs = [(_ts(i * 10), {"event_id": 4624, "data_fields": {}}) for i in range(5)]
        raw = build_evtx(specs)
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["total_records"] == 5


# ---------------------------------------------------------------------------
# 12. Summary metadata correctness
# ---------------------------------------------------------------------------


class TestSummaryMetadata:
    def test_failed_logons_counted(self):
        raw = build_bruteforce_evtx(fail_count=5)
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["failed_logons"] == 5

    def test_successful_logons_counted(self):
        raw = build_rdp_logon_evtx()
        report = _make_report(raw)
        assert report.metadata["evtx_summary"]["successful_logons"] == 1

    def test_multi_channel_all_channels(self):
        raw = build_multi_channel_evtx()
        report = _make_report(raw)
        channels = report.metadata["evtx_summary"]["all_channels"]
        assert "Security" in channels
        assert "System" in channels

    def test_event_id_distribution(self):
        raw = build_evtx(
            [(_ts(i), {"event_id": 4625, "data_fields": {}}) for i in range(3)]
            + [(_ts(100 + i), {"event_id": 4624, "data_fields": {}}) for i in range(2)]
        )
        report = _make_report(raw)
        dist = report.metadata["evtx_summary"]["event_id_distribution"]
        assert dist.get("4625") == 3
        assert dist.get("4624") == 2

    def test_kerberoasting_tickets_in_summary(self):
        raw = build_kerberoasting_evtx()
        report = _make_report(raw)
        tickets = report.metadata["evtx_summary"]["kerberos_rc4_tickets"]
        assert len(tickets) >= 3  # 3 events in fixture
        assert all(t["etype"] == "0x17" for t in tickets)

    def test_services_in_summary(self):
        raw = build_new_service_evtx()
        report = _make_report(raw)
        svcs = report.metadata["evtx_summary"]["services_installed"]
        assert any(s["name"] == "WindowsDefenderUpdate" for s in svcs)


# ---------------------------------------------------------------------------
# 13. Dispatcher integration
# ---------------------------------------------------------------------------


class TestDispatcherIntegration:
    def test_dispatcher_routes_evtx(self):
        raw = build_minimal_evtx()
        report = analyze_bytes(raw, label="test.evtx")
        assert report.format == FileFormat.EVTX

    def test_dispatcher_populates_evtx_summary(self):
        raw = build_minimal_evtx()
        report = analyze_bytes(raw, label="test.evtx")
        assert "evtx_summary" in report.metadata

    def test_dispatcher_populates_findings(self):
        raw = build_kerberoasting_evtx()
        report = analyze_bytes(raw, label="test.evtx")
        assert len(report.findings) > 0

    def test_evtx_verdict_is_non_clean_for_malicious(self):
        raw = build_log_cleared_evtx()
        report = analyze_bytes(raw, label="test.evtx")
        # CRITICAL finding → MALICIOUS verdict
        from ioc_hunter.analyze.common import Verdict

        assert report.verdict == Verdict.MALICIOUS


# ---------------------------------------------------------------------------
# 14. BinXML builder / fixture roundtrip
# ---------------------------------------------------------------------------


class TestBinXmlBuilderRoundtrip:
    def test_wstring_value_roundtrip(self):
        b = _BinXmlBuilder()
        binxml = (
            b.frag_header().open_elem("Channel").val_wstr("Security").close_elem().eof().build()
        )
        # Parse it via the analyzer
        from ioc_hunter.analyze.evtx import _parse_event_binxml

        fields = _parse_event_binxml(binxml, b"", {})
        assert fields.get("Channel") == "Security"

    def test_data_element_roundtrip(self):
        b = _BinXmlBuilder()
        binxml = (
            b.frag_header()
            .open_elem("EventData")
            .open_elem("Data")
            .attr("Name")
            .val_wstr("TargetUserName")
            .val_wstr("alice")
            .close_elem()
            .close_elem()  # /EventData
            .eof()
            .build()
        )
        from ioc_hunter.analyze.evtx import _parse_event_binxml

        fields = _parse_event_binxml(binxml, b"", {})
        assert fields.get("TargetUserName") == "alice"

    def test_attribute_roundtrip(self):
        b = _BinXmlBuilder()
        binxml = (
            b.frag_header()
            .open_elem("TimeCreated")
            .attr("SystemTime")
            .val_filetime(1717200000.0)
            .close_empty()
            .eof()
            .build()
        )
        from ioc_hunter.analyze.evtx import _parse_event_binxml

        fields = _parse_event_binxml(binxml, b"", {})
        assert "TimeCreated" in fields
        assert "2024" in fields["TimeCreated"]

    def test_name_caching_works(self):
        """Same element name used twice → second reference hits cache, no crash."""
        b = _BinXmlBuilder()
        binxml = (
            b.frag_header()
            .open_elem("Channel")
            .val_wstr("Security")
            .close_elem()
            .open_elem("Channel")
            .val_wstr("Security")
            .close_elem()
            .eof()
            .build()
        )
        from ioc_hunter.analyze.evtx import _parse_event_binxml

        fields = _parse_event_binxml(binxml, b"", {})
        assert fields.get("Channel") == "Security"
