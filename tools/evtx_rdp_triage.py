#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


INTERESTING_EVENT_IDS = {4624, 4625, 4634, 4647, 4672, 4778, 4779, 1149}


def load_evtx_module():
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "python-evtx is required. Install with: python3 -m pip install python-evtx"
        ) from exc
    return Evtx


def strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def text_or_empty(node: ET.Element | None) -> str:
    return "" if node is None or node.text is None else node.text


def parse_event_xml(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)
    row: dict[str, str] = {}

    system = next((child for child in root if strip_ns(child.tag) == "System"), None)
    if system is not None:
        for child in system:
            name = strip_ns(child.tag)
            if name == "EventID":
                row["EventID"] = text_or_empty(child)
            elif name == "TimeCreated":
                row["TimeCreated"] = child.attrib.get("SystemTime", "")
            elif name == "Provider":
                row["Provider"] = child.attrib.get("Name", "")
            elif name == "Computer":
                row["Computer"] = text_or_empty(child)

    data_nodes = []
    for parent_name in ("EventData", "UserData"):
        parent = next((child for child in root if strip_ns(child.tag) == parent_name), None)
        if parent is None:
            continue
        data_nodes.extend(parent.iter())

    for node in data_nodes:
        tag = strip_ns(node.tag)
        if tag in {"Data", "Param"} or re.fullmatch(r"Param\d+", tag):
            key = node.attrib.get("Name") or node.attrib.get("name") or f"Param{len(row)}"
            if re.fullmatch(r"Param\d+", tag):
                key = tag
            row[key] = text_or_empty(node)

    if row.get("EventID") == "1149":
        row.setdefault("AccountName", row.get("Param1", ""))
        row.setdefault("DomainName", row.get("Param2", ""))
        row.setdefault("ClientAddress", row.get("Param3", ""))

    message = re.sub(r"\s+", " ", xml_text)
    row["_raw_match_context"] = message[:500]
    return row


def interesting(row: dict[str, str]) -> bool:
    try:
        event_id = int(row.get("EventID", "0"))
    except ValueError:
        return False
    if event_id not in INTERESTING_EVENT_IDS:
        return False
    if event_id in {4624, 4625}:
        return row.get("LogonType", "") in {"7", "10", "3", ""}
    return True


def extract_rows(paths: list[Path]) -> list[dict[str, str]]:
    Evtx = load_evtx_module()
    rows: list[dict[str, str]] = []
    for path in paths:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    row = parse_event_xml(record.xml())
                except Exception as exc:
                    print(f"SKIP parse_error path={path} error={exc}", file=sys.stderr)
                    continue
                if interesting(row):
                    row["SourceFile"] = str(path)
                    rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract RDP/login-relevant events from Windows .evtx logs."
    )
    parser.add_argument("evtx", nargs="+", type=Path)
    parser.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()

    rows = extract_rows(args.evtx)
    fieldnames = [
        "SourceFile",
        "TimeCreated",
        "Provider",
        "EventID",
        "Computer",
        "TargetUserName",
        "SubjectUserName",
        "IpAddress",
        "ClientAddress",
        "WorkstationName",
        "LogonType",
        "AuthenticationPackageName",
        "ProcessName",
        "ProcessId",
        "SessionName",
        "AccountName",
        "DomainName",
        "_raw_match_context",
    ]
    extra = sorted({key for row in rows for key in row if key not in fieldnames})
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames + extra, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"events={len(rows)} csv={args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
