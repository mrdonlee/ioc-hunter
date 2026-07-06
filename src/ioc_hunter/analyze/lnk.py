"""Windows Shortcut (.lnk) analyzer.

Since Microsoft blocked macros-from-the-internet in 2022, LNK files
became the default first-stage dropper (Qakbot, Emotet, IcedID,
Bumblebee all shipped LNK campaigns). The attack shape is always the
same: a shortcut whose target is a script host (``powershell.exe``,
``mshta.exe``, ``rundll32.exe``, ...) with the payload smuggled into
COMMAND_LINE_ARGUMENTS — often padded with hundreds of spaces so the
Properties dialog shows an innocent-looking prefix.

We parse the MS-SHLLINK structure directly:

1. ``ShellLinkHeader`` — LinkFlags, ShowCommand (7 = minimised =
   window-hiding tell), FILETIME timestamps (zeroed by builder kits).
2. ``LinkInfo`` — local base path, volume serial, UNC network path.
3. ``StringData`` — NAME / RELATIVE_PATH / WORKING_DIR / ARGUMENTS /
   ICON_LOCATION. Arguments are where the payload lives.
4. ``ExtraData`` — the TrackerDataBlock leaks the *builder's* NetBIOS
   machine name and MAC address (version-1 UUID node) — free
   attribution pivots; the EnvironmentVariableDataBlock carries
   env-var-only targets that evade naive target checks.

Anything after the terminal ExtraData block is overlay — LNKs have a
fixed structure, so appended bytes are a smuggled payload.

Reference:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
"""

from __future__ import annotations

import base64
import re

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Reader,
    Severity,
    shannon_entropy,
)

# ---------------------------------------------------------------------------
# Magic + header constants
# ---------------------------------------------------------------------------

#: HeaderSize (0x4C LE) + LinkCLSID {00021401-0000-0000-C000-000000000046}.
#: The first 16 bytes are unique enough for dispatch; the full 20 make
#: ``is_lnk`` strict.
LNK_HEADER_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")

_HEADER_SIZE = 0x4C

# LinkFlags bits we care about (MS-SHLLINK §2.1.1).
_HAS_LINK_TARGET_ID_LIST = 0x0001
_HAS_LINK_INFO = 0x0002
_HAS_NAME = 0x0004
_HAS_RELATIVE_PATH = 0x0008
_HAS_WORKING_DIR = 0x0010
_HAS_ARGUMENTS = 0x0020
_HAS_ICON_LOCATION = 0x0040
_IS_UNICODE = 0x0080
_HAS_EXP_STRING = 0x0200
_RUN_AS_USER = 0x2000

#: SW_SHOWMINNOACTIVE — the only documented value that hides the console
#: window from the victim. Legitimate shortcuts almost never use it.
_SW_SHOWMINNOACTIVE = 7
_SW_VALID = {1, 3, 7}

#: ExtraData block signatures.
_BLOCK_ENVIRONMENT = 0xA0000001
_BLOCK_TRACKER = 0xA0000003

#: FILETIME epoch offset (100ns ticks between 1601-01-01 and 1970-01-01).
_FILETIME_EPOCH = 116444736000000000

#: Cap on ExtraData blocks we walk — real LNKs have < 10.
_MAX_EXTRA_BLOCKS = 64

#: Bytes after the terminal block before we call it an overlay. A couple
#: of alignment NULs are normal; kilobytes are a payload.
_OVERLAY_THRESHOLD = 16


# ---------------------------------------------------------------------------
# Suspicious-target tables
# ---------------------------------------------------------------------------

#: Script hosts + LOLBins that have no business being a shortcut target
#: in user-facing files. Basename match, lowercase.
_SCRIPT_HOSTS: frozenset[str] = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
        "curl.exe",
        "forfiles.exe",
        "installutil.exe",
        "msbuild.exe",
        "hh.exe",
        "scriptrunner.exe",
        "conhost.exe",
    }
)

#: Icon sources used to make a script-host shortcut look like a document.
_DECOY_ICON_EXTS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png")
_DECOY_ICON_BINARIES = frozenset(
    {
        "shell32.dll",
        "imageres.dll",
        "wordpad.exe",
        "notepad.exe",
        "acrord32.exe",
        "winword.exe",
        "excel.exe",
    }
)

#: Double extensions that scream masquerade when the file is *.lnk.
_MASQUERADE_EXTS = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".txt",
    ".jpg",
    ".png",
    ".mp4",
    ".html",
)

# PowerShell accepts any unambiguous prefix of -EncodedCommand; malware
# uses -e / -ec / -enc / -encodedcommand. The argument is base64 of
# UTF-16LE script.
_ENCODED_PS_RE = re.compile(r"(?i)(?:^|\s)[-/]e(?:c|n(?:c\w*)?)?\s+([A-Za-z0-9+/=]{16,})")

_URL_RE = re.compile(r"(?i)\bhttps?://")

#: 40+ consecutive whitespace chars inside arguments — the classic
#: "push the payload past the Properties dialog" padding trick.
_WS_PAD_RE = re.compile(r"\s{40,}")

#: Windows shows ~260 chars of arguments in the shortcut Properties UI.
_ARGS_UI_LIMIT = 260


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def is_lnk(head: bytes) -> bool:
    return head[: len(LNK_HEADER_MAGIC)] == LNK_HEADER_MAGIC


def analyze_lnk(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    report.format = FileFormat.LNK
    r = Reader(raw)

    if not is_lnk(raw):
        report.add(
            Finding(
                rule="lnk.bad_header",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="LNK header magic/CLSID malformed.",
            )
        )
        return report

    link_flags = r.u32(20) or 0
    show_command = r.u32(60) or 0
    ctime = _filetime_to_unix(r.u64(28) or 0)
    wtime = _filetime_to_unix(r.u64(44) or 0)
    report.timestamp = wtime or ctime

    meta: dict[str, object] = {
        "link_flags": f"0x{link_flags:08x}",
        "show_command": show_command,
    }

    # ---- Walk the variable-length body ----------------------------------
    offset = _HEADER_SIZE
    offset = _skip_id_list(r, offset, link_flags)
    offset, link_info = _parse_link_info(r, offset, link_flags)
    meta.update(link_info)
    offset, strings = _parse_string_data(r, offset, link_flags)
    meta.update(strings)
    offset, extra = _parse_extra_data(r, offset)
    meta.update(extra)

    # ---- Overlay ---------------------------------------------------------
    trailing = raw[offset:]
    if len(trailing) > _OVERLAY_THRESHOLD:
        report.has_overlay = True
        report.overlay_size = len(trailing)
        report.overlay_entropy = shannon_entropy(trailing)
        report.add(
            Finding(
                rule="lnk.overlay_data",
                severity=Severity.HIGH,
                category="anomaly",
                message=f"{len(trailing):,} bytes appended after the shortcut structure "
                f"(entropy {report.overlay_entropy:.2f}) — LNKs are fixed-format; "
                "trailing data is a smuggled payload.",
            )
        )

    # ---- Behaviour findings ----------------------------------------------
    target = str(
        meta.get("local_base_path")
        or meta.get("relative_path")
        or meta.get("env_target")
        or meta.get("network_path")
        or ""
    )
    args = str(meta.get("arguments") or "")
    icon = str(meta.get("icon_location") or "")
    meta["effective_target"] = target
    report.metadata["lnk"] = meta

    # The command a victim actually runs can be smuggled into any string
    # field, not just ARGUMENTS: malformed samples inflate the WORKING_DIR
    # length so it swallows the padded command, and IDList-only targets
    # hide the LOLBin from the documented path fields entirely. So the
    # content heuristics scan every string field joined together.
    command_surface = "\n".join(
        v
        for v in (
            str(meta.get("name") or ""),
            str(meta.get("relative_path") or ""),
            str(meta.get("working_dir") or ""),
            args,
        )
        if v
    )

    _judge_target(report, target, args, icon, link_flags)
    _judge_arguments(report, command_surface)
    _judge_command_content(report, target, command_surface)
    _judge_presentation(report, show_command, ctime, wtime)

    if link_flags & _RUN_AS_USER:
        report.add(
            Finding(
                rule="lnk.run_as_user",
                severity=Severity.INFO,
                category="shortcut",
                message="RunAsUser flag set — shortcut asks for alternate credentials.",
            )
        )

    machine_id = meta.get("machine_id")
    mac = meta.get("mac_address")
    if machine_id or mac:
        report.add(
            Finding(
                rule="lnk.tracker_provenance",
                severity=Severity.INFO,
                category="forensics",
                message="TrackerDataBlock leaks the builder host's NetBIOS name"
                + (" and MAC address" if mac else "")
                + " — attribution pivot.",
                evidence=tuple(str(v) for v in (machine_id, mac) if v),
            )
        )

    return report


# ---------------------------------------------------------------------------
# Structure walkers. Each returns the offset just past what it consumed;
# on malformed input they return the offset unchanged so later stages
# degrade instead of exploding.
# ---------------------------------------------------------------------------


def _skip_id_list(r: Reader, offset: int, link_flags: int) -> int:
    if not link_flags & _HAS_LINK_TARGET_ID_LIST:
        return offset
    size = r.u16(offset)
    if size is None:
        return offset
    return offset + 2 + size


def _parse_link_info(r: Reader, offset: int, link_flags: int) -> tuple[int, dict[str, object]]:
    out: dict[str, object] = {}
    if not link_flags & _HAS_LINK_INFO:
        return offset, out
    li_size = r.u32(offset)
    li_hdr = r.u32(offset + 4)
    if li_size is None or li_hdr is None or li_size < 0x1C:
        return offset, out
    flags = r.u32(offset + 8) or 0

    if flags & 0x1:  # VolumeIDAndLocalBasePath
        vol_off = r.u32(offset + 12)
        lbp_off = r.u32(offset + 16)
        if vol_off:
            serial = r.u32(offset + vol_off + 8)
            if serial is not None:
                out["volume_serial"] = f"{serial:08X}"
        if lbp_off:
            path = r.cstr(offset + lbp_off, max_len=1024)
            if path:
                out["local_base_path"] = path

    if flags & 0x2:  # CommonNetworkRelativeLinkAndPathSuffix
        cnrl_off = r.u32(offset + 20)
        if cnrl_off:
            net_off = r.u32(offset + cnrl_off + 8)
            if net_off:
                net = r.cstr(offset + cnrl_off + net_off, max_len=1024)
                if net:
                    out["network_path"] = net

    return offset + li_size, out


_STRING_FIELDS = (
    (_HAS_NAME, "name"),
    (_HAS_RELATIVE_PATH, "relative_path"),
    (_HAS_WORKING_DIR, "working_dir"),
    (_HAS_ARGUMENTS, "arguments"),
    (_HAS_ICON_LOCATION, "icon_location"),
)


def _parse_string_data(r: Reader, offset: int, link_flags: int) -> tuple[int, dict[str, object]]:
    out: dict[str, object] = {}
    unicode = bool(link_flags & _IS_UNICODE)
    for flag, key in _STRING_FIELDS:
        if not link_flags & flag:
            continue
        count = r.u16(offset)
        if count is None:
            break
        offset += 2
        nbytes = count * 2 if unicode else count
        buf = r.slice(offset, nbytes)
        if buf is None:
            break
        offset += nbytes
        try:
            out[key] = buf.decode("utf-16-le" if unicode else "cp1252", errors="replace")
        except Exception:
            continue
    return offset, out


def _parse_extra_data(r: Reader, offset: int) -> tuple[int, dict[str, object]]:
    out: dict[str, object] = {}
    sigs: list[str] = []
    for _ in range(_MAX_EXTRA_BLOCKS):
        size = r.u32(offset)
        if size is None or size < 4:
            # Terminal block: BlockSize < 0x04 (usually four NULs).
            if size is not None:
                offset += 4
            break
        sig = r.u32(offset + 4) or 0
        # Every real ExtraData block signature is 0xA000000X. Anything else
        # means we walked off the rails (e.g. an obfuscated sample inflated a
        # StringData length and swallowed the block table) — stop rather than
        # emit garbage signatures.
        if not 0xA0000000 <= sig <= 0xA000000C:
            break
        sigs.append(f"0x{sig:08x}")
        if sig == _BLOCK_TRACKER and size >= 0x60:
            machine = r.slice(offset + 16, 16)
            if machine:
                out["machine_id"] = machine.split(b"\x00", 1)[0].decode("ascii", "replace")
            mac = _uuid_v1_mac(r.slice(offset + 48, 16))
            if mac:
                out["mac_address"] = mac
        elif sig == _BLOCK_ENVIRONMENT and size >= 0x314:
            ansi = r.cstr(offset + 8, max_len=260)
            uni = r.slice(offset + 268, 520)
            target = ""
            if uni:
                target = uni.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
            out["env_target"] = target or (ansi or "")
        offset += size
    if sigs:
        out["extra_blocks"] = sigs
    return offset, out


def _uuid_v1_mac(guid: bytes | None) -> str | None:
    """Extract the MAC node from an on-disk version-1 UUID (Droid file id)."""
    if not guid or len(guid) != 16:
        return None
    time_hi = int.from_bytes(guid[6:8], "little")
    if time_hi >> 12 != 1:  # not a version-1 (time+node) UUID
        return None
    node = guid[10:16]
    if node == b"\x00" * 6:
        return None
    return ":".join(f"{b:02x}" for b in node)


def _filetime_to_unix(ft: int) -> int:
    if ft <= _FILETIME_EPOCH:
        return 0
    return (ft - _FILETIME_EPOCH) // 10_000_000


# ---------------------------------------------------------------------------
# Behaviour judges
# ---------------------------------------------------------------------------


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def _judge_target(
    report: AnalyzerReport, target: str, args: str, icon: str, link_flags: int
) -> None:
    base = _basename(target)

    if base in _SCRIPT_HOSTS:
        # A bare script-host target with no arguments is also the shape of the
        # legitimate "Windows PowerShell" / "Command Prompt" Start-Menu
        # shortcut — worth a look (MEDIUM) but not malicious on its own. Add
        # arguments and it becomes the weaponised dropper shape (HIGH).
        has_args = bool(args.strip())
        report.add(
            Finding(
                rule="lnk.script_host_target",
                severity=Severity.HIGH if has_args else Severity.MEDIUM,
                category="shortcut",
                message=f"Shortcut target is a script host / LOLBin ({base})"
                + (
                    " with arguments — standard first-stage dropper shape."
                    if has_args
                    else " — unusual for a user-facing shortcut."
                ),
                evidence=(target,) + ((args[:200],) if has_args else ()),
            )
        )
        icon_base = _basename(icon)
        if icon and (icon.lower().endswith(_DECOY_ICON_EXTS) or icon_base in _DECOY_ICON_BINARIES):
            report.add(
                Finding(
                    rule="lnk.icon_masquerade",
                    severity=Severity.HIGH,
                    category="shortcut",
                    message="Script-host target dressed with a document/system icon — "
                    "masquerading as a harmless file.",
                    evidence=(icon,),
                )
            )

    if target.startswith("\\\\"):
        report.add(
            Finding(
                rule="lnk.unc_target",
                severity=Severity.MEDIUM,
                category="shortcut",
                message="Shortcut target is a UNC network path — payload lives off-host.",
                evidence=(target,),
            )
        )

    # Env-var-only target: no IDList, no LinkInfo, everything hidden in
    # the EnvironmentVariableDataBlock — evades tools that only read the
    # documented target fields.
    if (
        link_flags & _HAS_EXP_STRING
        and not link_flags & (_HAS_LINK_TARGET_ID_LIST | _HAS_LINK_INFO)
        and report.metadata.get("lnk", {}).get("env_target")
    ):
        report.add(
            Finding(
                rule="lnk.env_target_only",
                severity=Severity.LOW,
                category="shortcut",
                message="Target expressed only via environment-variable block — "
                "hides the real target from naive parsers.",
                evidence=(str(report.metadata["lnk"]["env_target"]),),
            )
        )

    # foo.pdf.lnk / invoice.doc.lnk — the double-extension lure.
    name = _basename(report.path)
    if name.endswith(".lnk"):
        stem = name[:-4]
        if stem.endswith(_MASQUERADE_EXTS):
            report.add(
                Finding(
                    rule="lnk.double_extension",
                    severity=Severity.HIGH,
                    category="shortcut",
                    message=f"Double extension ({stem}.lnk) — shortcut posing as a document.",
                    evidence=(name,),
                )
            )


def _judge_arguments(report: AnalyzerReport, command: str) -> None:
    """Content heuristics over the combined command surface (arguments +
    the other string fields an obfuscated sample may hide the payload in).
    """
    if not command:
        return

    m = _ENCODED_PS_RE.search(command)
    if m:
        decoded_note = ""
        try:
            blob = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
            script = blob.decode("utf-16-le", errors="replace")
            decoded_note = script[:160]
            # Feed the decoded script into the shared strings + IOC sweep.
            existing = report.metadata.get("pdf_decoded_blob", b"")
            report.metadata["pdf_decoded_blob"] = existing + script.encode(
                "utf-8", errors="replace"
            )
        except Exception:
            pass
        report.add(
            Finding(
                rule="lnk.encoded_powershell",
                severity=Severity.CRITICAL,
                category="shortcut",
                message="Base64 -EncodedCommand PowerShell payload in shortcut command line.",
                evidence=tuple(v for v in (m.group(1)[:80], decoded_note) if v),
            )
        )

    if _WS_PAD_RE.search(command):
        report.add(
            Finding(
                rule="lnk.whitespace_padding",
                severity=Severity.HIGH,
                category="shortcut",
                message="Long whitespace run inside the command line — pads the payload "
                "past what the Properties dialog shows.",
            )
        )

    if len(command) > _ARGS_UI_LIMIT:
        report.add(
            Finding(
                rule="lnk.oversized_arguments",
                severity=Severity.MEDIUM,
                category="shortcut",
                message=f"Command line is {len(command):,} chars — beyond what the shortcut "
                "Properties UI displays.",
            )
        )

    if _URL_RE.search(command):
        report.add(
            Finding(
                rule="lnk.url_in_arguments",
                severity=Severity.MEDIUM,
                category="shortcut",
                message="URL embedded in shortcut command line — likely remote payload fetch.",
            )
        )


def _judge_command_content(report: AnalyzerReport, target: str, command: str) -> None:
    """Catch a script host / LOLBin invoked from *inside* the command surface.

    When the target lives only in the IDList (which we don't fully parse)
    or is smuggled into an over-long WORKING_DIR, ``_judge_target`` sees an
    empty target and misses the LOLBin. Here we look for a script-host
    basename referenced in the command text itself — but only fire when
    ``_judge_target`` did not already flag the target, to avoid a duplicate.
    """
    if not command or _basename(target) in _SCRIPT_HOSTS:
        return
    lowered = command.lower()
    hosts = sorted({h for h in _SCRIPT_HOSTS if h in lowered})
    # A bare path mention isn't enough; require a shell-exec indicator so a
    # working dir that merely lives under ...\WindowsPowerShell\... stays clean.
    exec_markers = ("/c ", "/k ", "-c ", "-enc", "-nop", "-w hidden", "-e ", "iex", "invoke-")
    if hosts and any(mark in lowered for mark in exec_markers):
        report.add(
            Finding(
                rule="lnk.lolbin_in_command",
                severity=Severity.HIGH,
                category="shortcut",
                message=f"Script host / LOLBin invoked from the shortcut command line "
                f"({', '.join(hosts)}) — payload hidden outside the documented target.",
                evidence=(command[:200],),
            )
        )


def _judge_presentation(report: AnalyzerReport, show_command: int, ctime: int, wtime: int) -> None:
    if show_command == _SW_SHOWMINNOACTIVE:
        report.add(
            Finding(
                rule="lnk.hidden_window",
                severity=Severity.HIGH,
                category="shortcut",
                message="ShowCommand = SW_SHOWMINNOACTIVE — console window hidden from "
                "the victim on launch.",
            )
        )
    elif show_command not in _SW_VALID:
        report.add(
            Finding(
                rule="lnk.nonstandard_showcommand",
                severity=Severity.LOW,
                category="anomaly",
                message=f"Undocumented ShowCommand value {show_command} — "
                "hand-crafted / builder-generated shortcut.",
            )
        )

    if ctime == 0 and wtime == 0:
        report.add(
            Finding(
                rule="lnk.zeroed_timestamps",
                severity=Severity.LOW,
                category="anomaly",
                message="Target FILETIMEs zeroed — builder kits scrub them; Explorer "
                "never writes shortcuts this way.",
            )
        )
