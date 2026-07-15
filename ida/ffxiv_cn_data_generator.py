#!/usr/bin/env python3

"""Generate an exact-only CN data file from a migration report."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


class HexInt(int):
    pass


class HexSafeDumper(yaml.SafeDumper):
    pass


def represent_hex_int(dumper: yaml.Dumper, value: HexInt):
    return dumper.represent_scalar("tag:yaml.org,2002:int", f"0x{value:X}")


HexSafeDumper.add_representer(HexInt, represent_hex_int)


def load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def exact_cn_addresses(report: dict[str, Any]) -> dict[tuple[str, str], int]:
    metadata = report["metadata"]
    if not metadata.get("global_baseline_available"):
        raise ValueError("The report has no global executable baseline")
    if metadata.get("data_version") != metadata.get("cn_game_version"):
        raise ValueError("data.yml and CN game versions do not match")

    addresses = {}
    targets = {}
    for result in report["results"]:
        if result["status"] != "exact":
            continue
        class_name = result["class"]
        member_name = result["member"]
        if not member_name or result["kind"] == "static_address":
            continue

        data_address = int(result["data_address"], 16)
        global_match = result["global"]
        cn_match = result["cn"]
        if global_match["match_count"] != 1 or cn_match["match_count"] != 1:
            raise ValueError(f"Non-unique exact result: {class_name}.{member_name}")
        if int(global_match["matches"][0]["target"], 16) != data_address:
            raise ValueError(f"Global address mismatch: {class_name}.{member_name}")
        if not cn_match["matches"][0]["target_in_text"]:
            raise ValueError(f"CN target is outside .text: {class_name}.{member_name}")

        cn_address = int(cn_match["matches"][0]["target"], 16)
        key = class_name, member_name
        if key in addresses:
            raise ValueError(f"Duplicate class/member result: {class_name}.{member_name}")
        if cn_address in targets:
            previous = targets[cn_address]
            raise ValueError(
                f"Duplicate CN target 0x{cn_address:X}: {previous} and {class_name}.{member_name}"
            )
        addresses[key] = cn_address
        targets[cn_address] = f"{class_name}.{member_name}"
    return addresses


def build_data_cn(
    source: dict[str, Any], report: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, int]]:
    exact = exact_cn_addresses(report)
    classes = {}
    written = set()
    for class_name, class_data in (source.get("classes") or {}).items():
        if not class_data:
            continue
        functions = {}
        for _, member_name in (class_data.get("funcs") or {}).items():
            key = class_name, member_name
            if key not in exact:
                continue
            functions[HexInt(exact[key])] = member_name
            written.add(key)
        if functions:
            classes[class_name] = {"funcs": functions}

    missing = sorted(set(exact) - written)
    if missing:
        class_name, member_name = missing[0]
        raise ValueError(
            f"Exact report result is absent from data.yml: {class_name}.{member_name}"
        )

    output = {
        "version": report["metadata"]["cn_game_version"],
        "classes": classes,
    }
    stats = {
        "exact_functions": len(written),
        "classes": len(classes),
        "unresolved_class_functions": report["summary"]["class_functions"]
        - len(written),
    }
    return output, stats


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=script_dir / "data.yml")
    parser.add_argument(
        "--report", type=Path, default=script_dir / "cn-migration-report.yml"
    )
    parser.add_argument("--output", type=Path, default=script_dir / "data_cn.yml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output, stats = build_data_cn(load_yaml(args.data), load_yaml(args.report))
    args.output.write_text(
        yaml.dump(
            output,
            Dumper=HexSafeDumper,
            sort_keys=False,
            allow_unicode=True,
            width=4096,
        ),
        encoding="utf-8",
    )
    print(yaml.safe_dump(stats, sort_keys=False).strip())
    print(f"CN data: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
