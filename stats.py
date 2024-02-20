#!/usr/bin/env python3
import csv
import os
import sys
from collections import Counter, defaultdict

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes

MANIFEST_URL = "https://euicc-manual.septs.app/docs/pki/ci/manifest.json"


def walk(dirname: str):
    for base_path, _, files in os.walk(dirname):
        for file in files:
            if file == "tls.pem":
                continue
            if not file.endswith(".pem"):
                continue
            yield os.path.join(base_path, file)


def get_manifest() -> list[dict]:
    response = requests.get(MANIFEST_URL)
    response.raise_for_status()
    return response.json()


def get_certificates():
    certificates = defaultdict(set)
    for file in walk("certificates"):
        with open(file, "rb") as fp:
            certificate = x509.load_pem_x509_certificate(fp.read())
            issuer = certificate.extensions. \
                get_extension_for_class(x509.AuthorityKeyIdentifier). \
                value.key_identifier.hex()
            certificates[issuer].add(certificate.fingerprint(hashes.SHA1()).hex())
    return certificates


def get_issuers():
    issuers = Counter()
    with open("records.csv", "r", newline="") as fp:
        rows = list(csv.DictReader(fp))
        for row in rows:
            issuers[row["issuer"]] += 1 if row["key_id"] else 0
    return dict(sorted(issuers.items(), key=lambda _: (_[1], _[0]), reverse=True))


def main():
    manifest = get_manifest()
    certificates = get_certificates()
    field_names = ["issuer", "rsp_count", "derive_keys", "name"]
    writer = csv.DictWriter(sys.stdout, fieldnames=field_names)
    writer.writeheader()
    for issuer, rsp_count in get_issuers().items():
        names = (r["name"] for r in manifest if issuer.startswith(r["key-id"]))
        writer.writerow({
            "issuer": issuer,
            "rsp_count": rsp_count,
            "derive_keys": len(certificates[issuer]),
            "name": next(names, None),
        })


if __name__ == "__main__":
    main()
