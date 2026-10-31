"""
pa2.py - Fleet Compliance Auditor for NET2008 Practical Assessment 2.

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


def version_tuple(text):
    """Turn a dotted version string such as "15.10" into a tuple (15, 10)."""
    return tuple(int(part) for part in str(text).strip().split("."))


def is_older(found, required):
    """Return True when version found is lower than version required."""
    found_parts = version_tuple(found)
    required_parts = version_tuple(required)
    length = max(len(found_parts), len(required_parts))
    found_parts = found_parts + (0,) * (length - len(found_parts))
    required_parts = required_parts + (0,) * (length - len(required_parts))
    return found_parts < required_parts


class Device:
    """One network device taken from the inventory XML."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        """Store the device fields; interfaces is a list of (name, status)."""
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces

    def has_owner(self):
        """Return True when the device has a non-blank owner."""
        return bool(self.owner and self.owner.strip())

    def down_count(self):
        """Return how many interfaces have the status "down"."""
        return sum(1 for _, status in self.interfaces if status == "down")


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
            Device(
                device_id=device_id,
                role=element.get("role"),
                os_version=element.get("os"),
                owner=owner,
                interfaces=interfaces,
            )
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


def device_violations(device, policy):
    """Return the list of violation objects for one device."""
    found = []

    min_os = policy.get("min_os")
    if isinstance(min_os, dict):
        if device.role not in min_os:
            found.append({
                "device": device.device_id,
                "type": "unknown_role",
                "role": device.role,
            })
        else:
            required = str(min_os[device.role])
            actual = str(device.os_version)
            try:
                outdated = is_older(actual, required)
            except ValueError:
                outdated = False
            if outdated:
                found.append({
                    "device": device.device_id,
                    "type": "os_outdated",
                    "found": actual,
                    "required": required,
                })

    if policy.get("require_owner") is True and not device.has_owner():
        found.append({"device": device.device_id, "type": "missing_owner"})

    max_down = policy.get("max_down_interfaces")
    if max_down is not None:
        down = device.down_count()
        if down > int(max_down):
            found.append({
                "device": device.device_id,
                "type": "too_many_down",
                "down": down,
            })

    return found


def build_report(site, devices, skipped, policy):
    """Build the complete audit report dictionary."""
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}
    violations = []
    compliant = []

    for device in devices:
        roles[device.role] = roles.get(device.role, 0) + 1

        for _, status in device.interfaces:
            if status == "up":
                interfaces["up"] += 1
            elif status == "down":
                interfaces["down"] += 1
            else:
                interfaces["other"] += 1

        problems = device_violations(device, policy)
        violations.extend(problems)
        if not problems:
            compliant.append(device.device_id)

    return {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant),
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

    try:
        with open("audit.json", "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    except OSError as error:
        print(f"error: cannot write audit.json: {error}")
        return 1

    print(f"site: {report['site']}")
    print(f"devices: {report['total_devices']} (skipped {report['skipped_devices']})")
    print(f"violations: {len(report['violations'])}")
    print(f"compliant: {len(report['compliant'])}")
    print("report written to audit.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))