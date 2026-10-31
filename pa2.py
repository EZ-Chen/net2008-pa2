"""
pa2.py - Fleet Compliance Auditor (Tier 1).

Name: Eric
Student ID: 101376269

Usage:
    python pa2.py DEVICES.xml POLICY.yaml
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


class InputFileError(Exception):
    """Raised when an input file is missing, unreadable or malformed."""


class Device:
    """One network device taken from the inventory XML."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        """Store the device fields; interfaces is a list of (name, status)."""
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces


def read_inventory(path):
    """Read the XML inventory and return (site, devices, skipped_count)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise InputFileError(f"missing inventory file: {path}")
    try:
        root = ET.parse(file_path).getroot()
    except ET.ParseError as error:
        raise InputFileError(f"invalid XML in {path}: {error}") from error
    except OSError as error:
        raise InputFileError(f"cannot read {path}: {error}") from error

    devices = []
    skipped = 0
    for element in root.findall("device"):
        device_id = element.get("id")
        if not device_id:
            skipped += 1
            continue
        owner_element = element.find("owner")
        owner = owner_element.text if owner_element is not None else None
        interfaces = [
            (item.get("name"), item.get("status"))
            for item in element.findall("interface")
        ]
        devices.append(
            Device(device_id, element.get("role"), element.get("os"),
                   owner, interfaces)
        )
    return root.get("site"), devices, skipped


def read_policy(path):
    """Read the YAML policy file and return it as a dictionary."""
    file_path = Path(path)
    if not file_path.is_file():
        raise InputFileError(f"missing policy file: {path}")
    try:
        with open(file_path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as error:
        raise InputFileError(f"invalid YAML in {path}: {error}") from error
    except OSError as error:
        raise InputFileError(f"cannot read {path}: {error}") from error

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise InputFileError(f"policy in {path} is not a mapping")
    return data


def build_report(site, devices, skipped, policy):
    """Build the Tier 1 audit report dictionary."""
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}

    for device in devices:
        roles[device.role] = roles.get(device.role, 0) + 1
        for _, status in device.interfaces:
            if status in ("up", "down"):
                interfaces[status] += 1
            else:
                interfaces["other"] += 1

    return {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": roles,
        "interfaces": interfaces,
        "violations": [],
        "compliant": sorted(device.device_id for device in devices),
    }


def main(argv):
    """Read the inputs, write audit.json and print a short summary."""
    if len(argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2

    try:
        site, devices, skipped = read_inventory(argv[1])
        policy = read_policy(argv[2])
    except InputFileError as error:
        print(f"error: {error}")
        return 1

    report = build_report(site, devices, skipped, policy)
    with open("audit.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print(f"site: {report['site']}")
    print(f"devices: {report['total_devices']} (skipped {report['skipped_devices']})")
    print("report written to audit.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))