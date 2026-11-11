#!/usr/bin/env python3
"""Prepare a retained local volume for an installation on one Linux node."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

STORAGE_ROOT = Path("/var/lib/registry-stack/storage")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def volume_documents(namespace, claim, node, size):
    if not all(LABEL.fullmatch(value) for value in (namespace, claim)):
        raise ValueError("Namespace and claim must be DNS labels.")
    if len(node) > 253 or not all(LABEL.fullmatch(label) for label in node.split(".")):
        raise ValueError("Node must be its Kubernetes hostname label.")
    if not re.fullmatch(r"[1-9][0-9]{0,5}(?:Mi|Gi|Ti)", size):
        raise ValueError("Capacity must be a positive whole number in Mi, Gi or Ti.")
    identity = hashlib.sha256(f"{namespace}/{claim}".encode()).hexdigest()[:12]
    volume = f"registry-local-{namespace}-{claim}-{identity}"
    pv = {
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {"name": volume},
        "spec": {
            "capacity": {"storage": size},
            "accessModes": ["ReadWriteOnce"],
            "volumeMode": "Filesystem",
            "persistentVolumeReclaimPolicy": "Retain",
            "storageClassName": "",
            "claimRef": {"namespace": namespace, "name": claim},
            "local": {"path": str(STORAGE_ROOT / namespace / claim)},
            "nodeAffinity": {
                "required": {"nodeSelectorTerms": [{"matchExpressions": [
                    {"key": "kubernetes.io/hostname", "operator": "In", "values": [node]},
                ]}]},
            },
        },
    }
    pvc = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"namespace": namespace, "name": claim},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "",
            "volumeMode": "Filesystem",
            "volumeName": volume,
            "resources": {"requests": {"storage": size}},
        },
    }
    return pv, pvc


def prepare_directory(path, uid, gid):
    if os.geteuid() != 0 or sys.platform != "linux":
        raise ValueError("Run --prepare-directory as root on the selected Linux node.")
    for parent in reversed(path.parents):
        parent.mkdir(mode=0o755, exist_ok=True)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"Storage parent {parent} must be a root-owned, non-writable directory.")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
            uid, gid, 0o700,
        ):
            raise ValueError(f"Existing path {path} needs review. Expected {uid}:{gid} and mode 0700.")
    else:
        os.chown(path, uid, gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--size", required=True)
    parser.add_argument("--prepare-directory", action="store_true")
    parser.add_argument("--owner", metavar="UID:GID")
    args = parser.parse_args()
    try:
        pv, pvc = volume_documents(args.namespace, args.claim, args.node, args.size)
        if args.prepare_directory:
            if not args.owner or not re.fullmatch(r"[1-9][0-9]{0,8}:[1-9][0-9]{0,8}", args.owner):
                raise ValueError("--prepare-directory needs --owner UID:GID with non-root numeric IDs.")
            uid, gid = (int(value) for value in args.owner.split(":"))
            prepare_directory(Path(pv["spec"]["local"]["path"]), uid, gid)
    except (OSError, ValueError) as error:
        parser.exit(1, f"local-volume: {error}\n")
    print(json.dumps({"apiVersion": "v1", "kind": "List", "items": [pv, pvc]}, indent=2))


if __name__ == "__main__":
    main()
