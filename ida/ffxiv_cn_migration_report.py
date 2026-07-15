#!/usr/bin/env python3

"""Build a read-only report for porting FFXIVClientStructs IDA data to CN."""

from __future__ import annotations

import argparse
import json
import os
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


IMAGE_BASE = 0x140000000
MAX_REPORTED_MATCHES = 2


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains_va(self, va: int, image_base: int) -> bool:
        rva = va - image_base
        return self.virtual_address <= rva < self.virtual_address + self.virtual_size


@dataclass(frozen=True)
class SignatureEntry:
    kind: str
    class_name: str
    member_name: str | None
    signature: str
    relative_follow_offsets: tuple[int, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return self.class_name, self.member_name or "<static-address>"


@dataclass(frozen=True)
class CompiledPattern:
    signature: str
    values: bytes
    fixed: tuple[bool, ...]
    anchor: bytes
    anchor_offset: int


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError(f"Not a PE file: {path}")

        section_count = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, pe_offset + 20)[0]
        optional_offset = pe_offset + 24
        magic = struct.unpack_from("<H", self.data, optional_offset)[0]
        if magic != 0x20B:
            raise ValueError(f"Expected a PE32+ image: {path}")

        self.image_base = struct.unpack_from("<Q", self.data, optional_offset + 24)[0]
        section_offset = optional_offset + optional_size
        sections = []
        for index in range(section_count):
            offset = section_offset + index * 40
            name = self.data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, offset + 8
            )
            sections.append(
                Section(name, virtual_address, virtual_size, raw_offset, raw_size)
            )
        self.sections = tuple(sections)

        text = next((section for section in self.sections if section.name == ".text"), None)
        if text is None:
            raise ValueError(f".text section not found: {path}")
        self.text_section = text
        self.text = self.data[text.raw_offset : text.raw_offset + text.raw_size]

    def text_offset_to_va(self, offset: int) -> int:
        return self.image_base + self.text_section.virtual_address + offset

    def contains_text_va(self, va: int) -> bool:
        return self.text_section.contains_va(va, self.image_base)

    def contains_image_va(self, va: int) -> bool:
        return any(section.contains_va(va, self.image_base) for section in self.sections)

    def va_to_raw_offset(self, va: int) -> int | None:
        rva = va - self.image_base
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + section.raw_size:
                return section.raw_offset + rva - section.virtual_address
        return None

    def read_i32(self, va: int) -> int | None:
        raw_offset = self.va_to_raw_offset(va)
        if raw_offset is None or raw_offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<i", self.data, raw_offset)[0]

    def game_version(self) -> str | None:
        version_path = self.path.parent / "ffxivgame.ver"
        if not version_path.is_file():
            return None
        return version_path.read_text(encoding="utf-8-sig").strip()


def compile_pattern(signature: str) -> CompiledPattern:
    tokens = signature.split()
    values = bytes(0 if token == "??" else int(token, 16) for token in tokens)
    fixed = tuple(token != "??" for token in tokens)

    best_start = 0
    best_length = 0
    run_start = 0
    run_length = 0
    for index, is_fixed in enumerate(fixed + (False,)):
        if is_fixed:
            if run_length == 0:
                run_start = index
            run_length += 1
        else:
            if run_length > best_length:
                best_start = run_start
                best_length = run_length
            run_length = 0

    if best_length == 0:
        raise ValueError(f"Signature has no fixed bytes: {signature}")
    return CompiledPattern(
        signature,
        values,
        fixed,
        values[best_start : best_start + best_length],
        best_start,
    )


def pattern_matches(data: bytes, start: int, pattern: CompiledPattern) -> bool:
    if start < 0 or start + len(pattern.values) > len(data):
        return False
    return all(
        not is_fixed or data[start + index] == pattern.values[index]
        for index, is_fixed in enumerate(pattern.fixed)
    )


def find_matches(image: PeImage, pattern: CompiledPattern) -> tuple[list[int], bool]:
    matches = []
    search_from = 0
    while True:
        anchor_at = image.text.find(pattern.anchor, search_from)
        if anchor_at < 0:
            return matches, False
        candidate = anchor_at - pattern.anchor_offset
        if pattern_matches(image.text, candidate, pattern):
            matches.append(image.text_offset_to_va(candidate))
            if len(matches) == MAX_REPORTED_MATCHES:
                return matches, True
        search_from = anchor_at + 1


def resolve_control_flow_target(image: PeImage, match_va: int) -> tuple[int, str]:
    raw_offset = image.va_to_raw_offset(match_va)
    if raw_offset is None:
        return match_va, "invalid"
    data = image.data
    opcode = data[raw_offset]
    if opcode in (0xE8, 0xE9) and raw_offset + 5 <= len(data):
        relative = struct.unpack_from("<i", data, raw_offset + 1)[0]
        kind = "call-rel32" if opcode == 0xE8 else "jump-rel32"
        return match_va + 5 + relative, kind
    if opcode == 0xEB and raw_offset + 2 <= len(data):
        relative = struct.unpack_from("<b", data, raw_offset + 1)[0]
        return match_va + 2 + relative, "jump-rel8"
    if 0x70 <= opcode <= 0x7F and raw_offset + 2 <= len(data):
        relative = struct.unpack_from("<b", data, raw_offset + 1)[0]
        return match_va + 2 + relative, "conditional-jump-rel8"
    if (
        opcode == 0x0F
        and raw_offset + 6 <= len(data)
        and 0x80 <= data[raw_offset + 1] <= 0x8F
    ):
        relative = struct.unpack_from("<i", data, raw_offset + 2)[0]
        return match_va + 6 + relative, "conditional-jump-rel32"
    return match_va, "direct"


def resolve_entry_target(
    image: PeImage, entry: SignatureEntry, match_va: int
) -> tuple[int | None, str]:
    if entry.kind != "static_address":
        return resolve_control_flow_target(image, match_va)

    target = match_va
    for offset in entry.relative_follow_offsets:
        displacement_at = target + offset
        displacement = image.read_i32(displacement_at)
        if displacement is None:
            return None, "invalid-static-address"
        target = displacement_at + 4 + displacement
    return target, "static-address"


def load_signature_entries(path: Path) -> list[SignatureEntry]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = []
    for struct_data in document.get("structs", []):
        class_name = struct_data["type"]
        for collection_name, kind in (
            ("member_functions", "member_function"),
            ("static_member_functions", "static_member_function"),
        ):
            for member in struct_data.get(collection_name, []) or []:
                entries.append(
                    SignatureEntry(kind, class_name, member["name"], member["signature"])
                )
        for member in struct_data.get("static_members", []) or []:
            entries.append(
                SignatureEntry(
                    "static_address",
                    class_name,
                    None,
                    member["signature"],
                    tuple(member.get("relative_follow_offsets", [])),
                )
            )
    return entries


def load_data_functions(path: Path) -> tuple[str | None, dict[tuple[str, str], int], dict[str, int]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    functions = {}
    for class_name, class_data in (document.get("classes") or {}).items():
        if not class_data:
            continue
        for address, name in (class_data.get("funcs") or {}).items():
            functions[(class_name, name)] = int(address)
    counts = {
        "class_functions": len(functions),
        "top_level_functions": len(document.get("functions") or {}),
        "globals": len(document.get("globals") or {}),
    }
    return document.get("version"), functions, counts


def launcher_exe(launcher_name: str) -> Path | None:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    config_path = Path(appdata) / launcher_name / "launcherConfigV3.json"
    if not config_path.is_file():
        return None
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    exe_path = Path(config["GamePath"]) / "game" / "ffxiv_dx11.exe"
    return exe_path if exe_path.is_file() else None


def scan_image(
    image: PeImage,
    patterns: dict[str, CompiledPattern],
    workers: int,
) -> dict[str, tuple[list[int], bool]]:
    items = list(patterns.items())

    def scan(item: tuple[str, CompiledPattern]):
        signature, pattern = item
        return signature, find_matches(image, pattern)

    if workers == 1:
        return dict(scan(item) for item in items)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return dict(executor.map(scan, items))


def match_details(
    image: PeImage,
    entry: SignatureEntry,
    scan: tuple[list[int], bool],
) -> dict[str, Any]:
    matches, truncated = scan
    resolved = []
    for match in matches:
        target, resolution = resolve_entry_target(image, entry, match)
        resolved.append(
            {
                "match": f"0x{match:X}",
                "target": f"0x{target:X}" if target is not None else None,
                "resolution": resolution,
                "target_in_image": target is not None and image.contains_image_va(target),
                "target_in_text": target is not None and image.contains_text_va(target),
            }
        )
    return {
        "match_count": f"{len(matches)}+" if truncated else len(matches),
        "matches": resolved,
    }


def unique_valid_target(details: dict[str, Any], require_text: bool) -> int | None:
    if details["match_count"] != 1:
        return None
    match = details["matches"][0]
    if not match["target_in_image"] or (require_text and not match["target_in_text"]):
        return None
    return int(match["target"], 16)


def classify(
    entry: SignatureEntry,
    expected_address: int | None,
    cn: dict[str, Any],
    global_details: dict[str, Any] | None,
) -> str:
    require_text = entry.kind != "static_address"
    cn_target = unique_valid_target(cn, require_text)
    if cn["match_count"] == 0:
        return "cn-missing"
    if cn["match_count"] != 1:
        return "cn-multiple"
    if cn_target is None:
        return "cn-invalid-target"
    if expected_address is None:
        return "cn-unique-unlinked"
    if global_details is None:
        return "cn-unique-unverified"

    global_target = unique_valid_target(global_details, require_text)
    if global_details["match_count"] == 0:
        return "global-missing"
    if global_details["match_count"] != 1:
        return "global-multiple"
    if global_target is None:
        return "global-invalid-target"
    if global_target != expected_address:
        return "global-address-mismatch"
    return "exact"


def make_report(
    data_path: Path,
    structs_path: Path,
    cn_image: PeImage,
    global_image: PeImage | None,
    workers: int,
) -> dict[str, Any]:
    data_version, data_functions, data_counts = load_data_functions(data_path)
    entries = load_signature_entries(structs_path)
    patterns = {entry.signature: compile_pattern(entry.signature) for entry in entries}

    cn_scans = scan_image(cn_image, patterns, workers)
    global_scans = (
        scan_image(global_image, patterns, workers) if global_image is not None else None
    )

    results = []
    status_counts: dict[str, int] = {}
    linked_status_counts: dict[str, int] = {}
    directly_linked = 0
    for entry in entries:
        expected_address = data_functions.get(entry.key)
        if expected_address is not None:
            directly_linked += 1
        cn_details = match_details(cn_image, entry, cn_scans[entry.signature])
        global_details = (
            match_details(global_image, entry, global_scans[entry.signature])
            if global_image is not None and global_scans is not None
            else None
        )
        status = classify(entry, expected_address, cn_details, global_details)
        status_counts[status] = status_counts.get(status, 0) + 1
        if expected_address is not None:
            linked_status_counts[status] = linked_status_counts.get(status, 0) + 1
        result = {
            "class": entry.class_name,
            "member": entry.member_name,
            "kind": entry.kind,
            "signature": entry.signature,
            "data_address": (
                f"0x{expected_address:X}" if expected_address is not None else None
            ),
            "status": status,
            "cn": cn_details,
        }
        if global_details is not None:
            result["global"] = global_details
        cn_target = unique_valid_target(
            cn_details, entry.kind != "static_address"
        )
        if cn_target is not None and expected_address is not None:
            result["address_delta"] = cn_target - expected_address
        results.append(result)

    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_file": str(data_path.resolve()),
            "structs_file": str(structs_path.resolve()),
            "data_version": data_version,
            "cn_exe": str(cn_image.path.resolve()),
            "cn_game_version": cn_image.game_version(),
            "global_exe": (
                str(global_image.path.resolve()) if global_image is not None else None
            ),
            "global_game_version": (
                global_image.game_version() if global_image is not None else None
            ),
            "global_baseline_available": global_image is not None,
            "writes_game_or_idb": False,
        },
        "summary": {
            **data_counts,
            "signature_entries": len(entries),
            "unique_signatures": len(patterns),
            "directly_linked_class_functions": directly_linked,
            "direct_signature_coverage": round(
                directly_linked / data_counts["class_functions"], 6
            ),
            "statuses": dict(sorted(status_counts.items())),
            "linked_statuses": dict(sorted(linked_status_counts.items())),
        },
        "results": results,
    }


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=script_dir / "data.yml")
    parser.add_argument("--structs", type=Path, default=script_dir / "ffxiv_structs.yml")
    parser.add_argument("--cn-exe", type=Path)
    parser.add_argument("--global-exe", type=Path)
    parser.add_argument(
        "--output", type=Path, default=script_dir / "cn-migration-report.yml"
    )
    parser.add_argument(
        "--workers", type=int, default=min(8, os.cpu_count() or 1)
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cn_exe = args.cn_exe or launcher_exe("XIVLauncherCN")
    if cn_exe is None or not cn_exe.is_file():
        raise FileNotFoundError("CN ffxiv_dx11.exe not found; pass --cn-exe")

    global_exe = args.global_exe or launcher_exe("XIVLauncher")
    if args.global_exe is not None and not args.global_exe.is_file():
        raise FileNotFoundError(args.global_exe)

    cn_image = PeImage(cn_exe)
    global_image = PeImage(global_exe) if global_exe is not None else None
    report = make_report(
        args.data,
        args.structs,
        cn_image,
        global_image,
        max(1, args.workers),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(report, sort_keys=False, allow_unicode=True, width=4096),
        encoding="utf-8",
    )
    print(yaml.safe_dump(report["summary"], sort_keys=False).strip())
    print(f"Report: {args.output.resolve()}")
    if global_image is None:
        print("Global executable unavailable; unique CN matches remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
