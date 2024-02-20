#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import logging
import os
import ssl
from base64 import b64decode, b64encode, encodebytes
from concurrent.futures import ThreadPoolExecutor, as_completed
from csv import DictReader, DictWriter
from datetime import datetime, timedelta, UTC
from subprocess import run
from tempfile import NamedTemporaryFile
from typing import Iterator
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

urllib3.disable_warnings()

BASE_PATH = "certificates"
RECORD_FILE = "records.csv"
CERTIFICATE_REGISTRY_FILE = "registry.csv"
SMDP_ADDRESSES_FILE = "SMDP-ADDRESSES"
SMDP_ISSUERS_FILE = "SMDP-ISSUERS"
API_ES9P_INIT_AUTH = "/gsma/rsp2/es9plus/initiateAuthentication"

UNAVAILABLE_RSP_ADDRESSES = {
    "rsp.esim.me:8083",  # inaccessible
    "rsp.esim.whty.com.cn",  # ip banned
}


@dataclasses.dataclass(frozen=True)
class Record:
    smdp_address: str
    issuer: str
    key_id: str


def get_hostname(host: str) -> str:
    return urlparse("//" + host).hostname


def get_peer_certificate(host: str):
    parsed = urlparse("//" + host)
    try:
        certificate = ssl.get_server_certificate((parsed.hostname, parsed.port or 443))
    except Exception as _:
        return None
    return x509.load_pem_x509_certificate(certificate.encode()).public_bytes(Encoding.DER)


def store_certificate_with_openssl(file_path: str, certificate: bytes):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as fp, NamedTemporaryFile() as stdin:
        stdin.write(certificate)
        stdin.seek(0)
        args = ["openssl", "x509", "-text", "-inform", "DER", "-in", stdin.name]
        run(args, stdout=fp, stderr=fp)


def get_euicc_info(issuer: str) -> str:
    payload = b"".join((
        b"\xBF\x20\x35\x82\x03\x02\x02\x00\xA9\x16\x04\x14",
        bytes.fromhex(issuer),
        b"\xaa\x16\x04\x14",
        bytes.fromhex(issuer),
    ))
    return encodebytes(payload).decode().strip()


def get_certificate(smdp_address: str, issuer: str) -> tuple[str, bytes | None]:
    headers = {
        "User-Agent": "gsma-rsp-lpad",
        "Content-Type": "application/json",
        "X-Admin-Protocol": "gsma/rsp/v2.2.0",
    }
    data = {
        "smdpAddress": smdp_address,
        "euiccChallenge": b64encode(os.urandom(16)).decode().strip(),
        "euiccInfo1": get_euicc_info(issuer),
    }
    response = requests.post(
        urlunparse(("https", smdp_address, API_ES9P_INIT_AUTH, "", "", "")),
        headers=headers,
        json=data,
        verify=False,
        timeout=10
    )
    logger = logging.getLogger(f"rsp:{smdp_address}:{issuer}")
    if not response.ok:
        logger.info(response.status_code)
        return issuer, None
    payload = response.json()
    execution = payload["header"]["functionExecutionStatus"]
    certificate = None
    if "serverCertificate" in payload:
        logger.info(execution["status"])
        certificate = b64decode(payload["serverCertificate"])
    elif "statusCodeData" in execution:
        logger.info(execution["statusCodeData"])
    else:
        logger.info(execution["status"])
    return issuer, certificate


def download_certificate(record: Record) -> Record:
    host = get_hostname(record.smdp_address)
    tls_file_path = os.path.join(os.path.join(BASE_PATH, host, "tls.pem"))
    # if not os.path.exists(tls_file_path):
    #     peer_certificate = get_peer_certificate(record.smdp_address)
    #     if peer_certificate:
    #         store_certificate_with_openssl(tls_file_path, peer_certificate)
    issuer, certificate = get_certificate(record.smdp_address, record.issuer)
    if not certificate:
        return Record(record.smdp_address, issuer, "")
    parsed_certificate = x509.load_der_x509_certificate(certificate)
    issuer = parsed_certificate.extensions. \
        get_extension_for_class(x509.AuthorityKeyIdentifier). \
        value.key_identifier.hex()
    key_id = parsed_certificate.extensions. \
        get_extension_for_class(x509.SubjectKeyIdentifier). \
        value.key_identifier.hex()
    file_path = os.path.join(os.path.join(BASE_PATH, host, f"{issuer}.pem"))
    store_certificate_with_openssl(file_path, certificate)
    return Record(record.smdp_address, issuer, key_id)


def get_records() -> tuple[set[str], set[str], list[Record]]:
    with open(RECORD_FILE, "r", newline="") as fp:
        rows: DictReader = DictReader(fp)
        records: list[Record] = [Record(row["smdp_address"], row["issuer"], row["key_id"]) for row in rows]
    issuers = {record.issuer for record in records}
    issuers.difference_update(map(str.strip, os.environ.get("SMDP_ISSUERS", "").split(";")))
    addresses = {record.smdp_address for record in records}
    addresses.difference_update(map(str.strip, os.environ.get("SMDP_ADDRESSES", "").split(";")))
    if os.path.exists(SMDP_ISSUERS_FILE):
        with open(SMDP_ISSUERS_FILE, "r", newline="") as fp:
            issuers.update(map(str.strip, fp.readlines()))
    if os.path.exists(SMDP_ADDRESSES_FILE):
        with open(SMDP_ADDRESSES_FILE, "r", newline="") as fp:
            addresses.update(map(str.strip, fp.readlines()))
    issuers = {_.lower() for _ in issuers if _ and len(bytes.fromhex(_)) == 20}
    addresses = {_.lower() for _ in addresses if _ and _ not in UNAVAILABLE_RSP_ADDRESSES}
    return issuers, addresses, records


def store_records(records: list[Record]):
    addresses = {r.smdp_address for r in records if r.key_id}
    records = set(records)
    records = [r for r in records if r.smdp_address in addresses]
    records = sorted(records, key=lambda r: (
        ".".join(reversed(get_hostname(r.smdp_address).split("."))),
        r.issuer
    ))
    with open(RECORD_FILE, "w", newline="") as fp:
        writer = DictWriter(fp, fieldnames=[f.name for f in dataclasses.fields(Record)])
        writer.writeheader()
        writer.writerows(dataclasses.asdict(r) for r in records)
    with open(CERTIFICATE_REGISTRY_FILE, "w", newline="") as fp:
        writer = DictWriter(fp, fieldnames=[f.name for f in dataclasses.fields(Record)])
        writer.writeheader()
        writer.writerows(dataclasses.asdict(r) for r in records if r.key_id)


def expand_incremental_records(records: list[Record], max_workers: int) -> Iterator[Record]:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_certificate, r): r for r in records}
        for future in as_completed(futures):
            record: Record = futures[future]
            actual_record: Record = future.result()
            yield actual_record if record.issuer == actual_record.issuer else record


def has_expired_record(address: str, issuer: str) -> bool:
    certificate_path = os.path.join(BASE_PATH, get_hostname(address), f"{issuer}.pem")
    if not os.path.exists(certificate_path):
        return False
    with open(certificate_path, "rb") as fp:
        certificate = x509.load_pem_x509_certificate(fp.read())
    delta = timedelta(seconds=certificate.not_valid_after_utc.timestamp() - datetime.now(UTC).timestamp())
    return -180 <= delta.days <= 0


def main():
    logging.basicConfig(level=logging.INFO)
    issuers, addresses, records = get_records()
    incremental_records = [
        Record(address, issuer, "")
        for address in addresses
        for issuer in issuers
        if not any(r.smdp_address == address and r.issuer == issuer for r in records)
    ]
    incremental_records += [
        Record(address, issuer, "")
        for address in addresses
        for issuer in issuers
        if has_expired_record(address, issuer)
    ]
    max_workers = min(max(len(issuers), 3), 15)
    with open(RECORD_FILE, "a+", newline="") as fp:
        writer = DictWriter(fp, fieldnames=[f.name for f in dataclasses.fields(Record)])
        for record in expand_incremental_records(incremental_records, max_workers):
            records.append(record)
            writer.writerow(dataclasses.asdict(record))
            fp.flush()
    store_records(records)


if __name__ == "__main__":
    main()
