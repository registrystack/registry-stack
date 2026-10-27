"""One SQLite transaction owns each command, state advance, and simulated credit."""

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import simplejson

from .models import ApiError, invalid, not_found

MAX_MINOR = 9007199254740991
SCHEMA_VERSION = 2
SCHEMA = """
CREATE TABLE mappings (
    tenant TEXT, institution TEXT, payee TEXT, mode TEXT, address TEXT NOT NULL, bank TEXT,
    PRIMARY KEY (tenant, institution, payee, mode)
);
CREATE TABLE commands (
    producer TEXT, tenant TEXT, operation TEXT, command_id TEXT,
    fingerprint TEXT NOT NULL, response TEXT NOT NULL,
    PRIMARY KEY (producer, tenant, operation, command_id)
);
CREATE TABLE scenarios (
    producer TEXT, tenant TEXT, name TEXT NOT NULL, reject_request TEXT,
    PRIMARY KEY (producer, tenant)
);
CREATE TABLE batches (
    batch_id TEXT PRIMARY KEY, producer TEXT NOT NULL, tenant TEXT NOT NULL,
    correlation TEXT NOT NULL, institution TEXT NOT NULL, program TEXT NOT NULL, payer TEXT NOT NULL,
    payload TEXT NOT NULL, started_at TEXT NOT NULL
);
CREATE TABLE instructions (
    transaction_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    producer TEXT NOT NULL, tenant TEXT NOT NULL, request_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL, currency TEXT NOT NULL, scale INTEGER NOT NULL,
    status TEXT NOT NULL, address TEXT, bank TEXT, error TEXT,
    started_at TEXT NOT NULL, completed_at TEXT,
    UNIQUE (producer, tenant, request_id)
);
CREATE TABLE credits (
    transaction_id TEXT PRIMARY KEY REFERENCES instructions(transaction_id),
    credited_at TEXT NOT NULL
);
"""

COLLECTION_SCHEMA = """
CREATE TABLE collection_scenarios (
    producer TEXT, tenant TEXT, biller TEXT, outcome TEXT NOT NULL,
    PRIMARY KEY (producer, tenant, biller)
);
CREATE TABLE collection_requests (
    transfer_id TEXT PRIMARY KEY, producer TEXT NOT NULL, tenant TEXT NOT NULL, biller TEXT NOT NULL,
    request_id TEXT NOT NULL, rtp_id INTEGER NOT NULL, bill_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL, currency TEXT NOT NULL, scale INTEGER NOT NULL,
    payload TEXT NOT NULL, outcome TEXT NOT NULL, stage INTEGER NOT NULL DEFAULT 0,
    last_update INTEGER NOT NULL,
    UNIQUE (producer, tenant, rtp_id), UNIQUE (producer, tenant, biller, bill_id)
);
CREATE TABLE collection_payments (
    transfer_id TEXT PRIMARY KEY REFERENCES collection_requests(transfer_id),
    reference TEXT NOT NULL UNIQUE, received_at INTEGER NOT NULL
);
"""


def dumps(value, **kwargs):
    return simplejson.dumps(value, use_decimal=True, allow_nan=False, ensure_ascii=False, **kwargs)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def decimal_parts(value):
    sign, digits, exponent = value.as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    return sign, digits, exponent


def minor_units(amount, scale):
    # Tuple arithmetic avoids Decimal context rounding and giant exponent allocation.
    sign, digits, exponent = decimal_parts(amount)
    exponent += scale
    if sign or exponent < 0 or len(digits) + exponent > 16:
        raise invalid("amount")
    units = int("".join(map(str, digits))) * 10**exponent
    if not 0 < units <= MAX_MINOR:
        raise invalid("amount")
    return units


def fingerprint(value):
    def canonical(item):
        if isinstance(item, Decimal):
            return ["number", decimal_parts(item)]
        if isinstance(item, dict):
            return ["object", [[key, canonical(val)] for key, val in sorted(item.items())]]
        if isinstance(item, list):
            return ["array", [canonical(val) for val in item]]
        return [type(item).__name__, item]

    encoded = json.dumps([1, canonical(value)], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True)
class Scope:
    producer: str
    tenant: str
    institution: str = ""
    program: str = ""
    callback: str = ""


class Store:
    def __init__(self, path, *, create=True):
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                # Keep an existing state file; its schema version is checked below.
                pass
        elif not self.path.is_file():
            raise ValueError("state file does not exist; start the simulator first")
        with self.connection(write=create) as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0 and create:
                if db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise ValueError("unrecognized database; choose a fresh state file")
                for statement in (SCHEMA + COLLECTION_SCHEMA).split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version == 1 and create:
                # A single additive upgrade preserves the original G2P demo state.
                # Keep it in this transaction; no reset or migration framework.
                for statement in COLLECTION_SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version != SCHEMA_VERSION:
                raise ValueError(
                    "incompatible database version; start serve to upgrade v1, "
                    "or choose a fresh state file"
                )

    @contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def receipt(self, db, scope, operation, command_id, body):
        digest = fingerprint(
            {
                "body": body,
                "institution": scope.institution,
                "program": scope.program,
                "callback": scope.callback,
            }
        )
        row = db.execute(
            "SELECT fingerprint, response FROM commands WHERE producer=? AND tenant=? "
            "AND operation=? AND command_id=?",
            (scope.producer, scope.tenant, operation, command_id),
        ).fetchone()
        if row and row["fingerprint"] != digest:
            raise ApiError(409, "request.id-reused", "Command identity already used")
        return digest, json.loads(row["response"]) if row else None

    def remember(self, db, scope, operation, command_id, digest, response):
        db.execute(
            "INSERT INTO commands VALUES (?, ?, ?, ?, ?, ?)",
            (scope.producer, scope.tenant, operation, command_id, digest, dumps(response)),
        )

    def write_mapping(self, scope, request, *, update=False):
        body = request.model_dump(exclude_none=True)
        operation = "update" if update else "register"
        command_id = body["requestID" if update else "RequestID"]
        items = body["beneficiaries" if update else "Beneficiaries"]
        with self.connection(write=True) as db:
            digest, replay = self.receipt(db, scope, operation, command_id, body)
            if replay is not None:
                return replay
            seen = set()
            for item in items:
                payee = item["payeeIdentity"]
                mode = item["paymentModality" if update else "PaymentModality"]
                if (payee, mode) in seen:
                    raise invalid("beneficiaries")
                seen.add((payee, mode))
                key = (scope.tenant, scope.institution, payee, mode)
                old = db.execute(
                    "SELECT address, bank FROM mappings WHERE tenant=? AND institution=? "
                    "AND payee=? AND mode=?",
                    key,
                ).fetchone()
                if update:
                    if old is None:
                        raise not_found()
                    db.execute(
                        "UPDATE mappings SET address=?, bank=? WHERE tenant=? AND institution=? "
                        "AND payee=? AND mode=?",
                        (
                            item.get("financialAddress", old["address"]),
                            item.get("bankingInstitutionCode", old["bank"]),
                            *key,
                        ),
                    )
                else:
                    if old is not None:
                        raise ApiError(409, "mapping.exists", "Mapping already exists")
                    db.execute(
                        "INSERT INTO mappings VALUES (?, ?, ?, ?, ?, ?)",
                        (*key, item["FinancialAddress"], item.get("bankingInstitutionCode")),
                    )
            response = {
                "responseCode": "00",
                "responseDescription": "Applied",
                "requestID": command_id,
            }
            self.remember(db, scope, operation, command_id, digest, response)
            return response

    def lookup(self, scope, payee, request_id):
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM mappings WHERE tenant=? AND institution=? AND payee=? ORDER BY mode",
                (scope.tenant, scope.institution, payee),
            ).fetchall()
        if not rows:
            raise not_found()
        return {
            "requestId": request_id,
            "paymentModalityList": [
                {
                    "payeeIdentity": payee,
                    "paymentModality": row["mode"],
                    "financialAddress": row["address"],
                    **({"bankingInstitutionCode": row["bank"]} if row["bank"] is not None else {}),
                }
                for row in rows
            ],
        }

    def accept(self, scope, correlation, request, currencies, modes):
        body = request.model_dump(exclude_none=True)
        with self.connection(write=True) as db:
            digest, replay = self.receipt(db, scope, "submit", correlation, body)
            if replay is not None:
                return replay
            # Current authority was checked by the route. New-work configuration
            # cannot invalidate a receipt or reinterpret its persisted scale.
            for item in request.root:
                if item.currency not in currencies:
                    raise invalid("currency")
                if item.paymentMode not in modes:
                    raise invalid("paymentMode")
            amounts = [minor_units(item.amount, currencies[item.currency]) for item in request.root]
            if sum(amounts) > MAX_MINOR:
                raise invalid("amount")
            if len({item.currency for item in request.root}) != 1:
                raise invalid("currency")
            if len({item.debitParty[0].value for item in request.root}) != 1:
                raise invalid("debitParty")
            if len({item.requestId for item in request.root}) != len(body):
                raise invalid("requestId")
            for item in request.root:
                if db.execute(
                    "SELECT 1 FROM instructions WHERE producer=? AND tenant=? AND request_id=?",
                    (scope.producer, scope.tenant, item.requestId),
                ).fetchone():
                    raise ApiError(409, "payment.id-reused", "Instruction identity already used")
            batch_id, started = str(uuid4()), now()
            db.execute(
                "INSERT INTO batches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    batch_id,
                    scope.producer,
                    scope.tenant,
                    correlation,
                    scope.institution,
                    scope.program,
                    request.root[0].debitParty[0].value,
                    dumps(body),
                    started,
                ),
            )
            scenario = db.execute(
                "SELECT * FROM scenarios WHERE producer=? AND tenant=?",
                (scope.producer, scope.tenant),
            ).fetchone()
            for item, units in zip(request.root, amounts, strict=True):
                mapping = db.execute(
                    "SELECT address, bank FROM mappings WHERE tenant=? AND institution=? "
                    "AND payee=? AND mode=?",
                    (scope.tenant, scope.institution, item.creditParty[0].value, item.paymentMode),
                ).fetchone()
                error = None
                if mapping is None:
                    error = "mapping-not-found"
                elif (
                    scenario
                    and scenario["name"] == "partial"
                    and (item.requestId == scenario["reject_request"])
                ):
                    error = "account-rejected"
                db.execute(
                    "INSERT INTO instructions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid4()),
                        batch_id,
                        scope.producer,
                        scope.tenant,
                        item.requestId,
                        units,
                        item.currency,
                        currencies[item.currency],
                        "PDNG",
                        mapping["address"] if mapping else None,
                        mapping["bank"] if mapping else None,
                        error,
                        started,
                        None,
                    ),
                )
            response = {"batchId": batch_id}
            self.remember(db, scope, "submit", correlation, digest, response)
            return response

    def details(self, scope, batch_id, correlation, page, size, institutions, programs, payers):
        with self.connection() as db:
            batch = db.execute(
                "SELECT * FROM batches WHERE batch_id=? AND producer=? AND tenant=?",
                (batch_id, scope.producer, scope.tenant),
            ).fetchone()
            if (
                batch is None
                or batch["institution"] not in institutions
                or batch["program"] not in programs
                or batch["payer"] not in payers
                or (correlation is not None and batch["correlation"] != correlation)
            ):
                raise not_found()
            rows = db.execute(
                "SELECT * FROM instructions WHERE batch_id=? ORDER BY request_id LIMIT ? OFFSET ?",
                (batch_id, size, page * size),
            ).fetchall()
        result = []
        for row in rows:
            item = {
                "requestId": row["request_id"],
                "transactionId": row["transaction_id"],
                "batchId": batch_id,
                "amount": Decimal(row["amount_minor"]).scaleb(-row["scale"]),
                "currency": row["currency"],
                "status": row["status"],
                "startedAt": row["started_at"],
                "direction": "OUTGOING",
            }
            if row["completed_at"] is not None:
                item["completedAt"] = row["completed_at"]
            if row["address"] is not None:
                item.update(payeePartyId=row["address"], payeePartyIdType="FINANCIAL_ADDRESS")
            if row["bank"] is not None:
                item["payeeDfspId"] = row["bank"]
            if row["status"] == "RJCT":
                item["errorInformation"] = row["error"]
            result.append(item)
        return result

    def scenario(self, producer, tenant, name, reject_request=None):
        with self.connection(write=True) as db:
            db.execute(
                "INSERT INTO scenarios VALUES (?, ?, ?, ?) ON CONFLICT(producer, tenant) "
                "DO UPDATE SET name=excluded.name, reject_request=excluded.reject_request",
                (producer, tenant, name, reject_request),
            )

    def advance(self, steps=1):
        for _ in range(steps):
            with self.connection(write=True) as db:
                rows = db.execute(
                    "SELECT transaction_id, status, error FROM instructions "
                    "WHERE status IN ('PDNG', 'ACSP')"
                ).fetchall()
                for row in rows:
                    transaction_id = row["transaction_id"]
                    if row["status"] == "PDNG":
                        db.execute(
                            "UPDATE instructions SET status='ACSP' WHERE transaction_id=?",
                            (transaction_id,),
                        )
                    else:
                        completed = now()
                        status = "RJCT" if row["error"] else "ACCC"
                        if status == "ACCC":
                            db.execute(
                                "INSERT INTO credits VALUES (?, ?)", (transaction_id, completed)
                            )
                        db.execute(
                            "UPDATE instructions SET status=?, completed_at=? WHERE transaction_id=?",
                            (status, completed, transaction_id),
                        )
                self.advance_collections(db)

    def request_collection(self, scope, request, currencies):
        payload = request.model_dump(exclude_none=True)
        with self.connection(write=True) as db:
            digest, replay = self.receipt(db, scope, "collection", request.requestId, payload)
            if replay is not None:
                return replay
            if request.billDetails.currency not in currencies:
                raise invalid("billDetails.currency")
            scale = currencies[request.billDetails.currency]
            amount = minor_units(request.billDetails.amount, scale)
            if db.execute(
                "SELECT 1 FROM collection_requests WHERE producer=? AND tenant=? AND rtp_id=?",
                (scope.producer, scope.tenant, request.rtpId),
            ).fetchone():
                raise ApiError(409, "payment.id-reused", "RTP identity already used")
            if db.execute(
                "SELECT 1 FROM collection_requests WHERE producer=? AND tenant=? AND biller=? "
                "AND bill_id=?",
                (scope.producer, scope.tenant, scope.institution, request.billID),
            ).fetchone():
                raise ApiError(409, "collection.bill-in-use", "Bill already has a payment request")
            scenario = db.execute(
                "SELECT outcome FROM collection_scenarios WHERE producer=? AND tenant=? AND biller=?",
                (scope.producer, scope.tenant, scope.institution),
            ).fetchone()
            transfer_id = str(uuid4())
            db.execute(
                "INSERT INTO collection_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    transfer_id,
                    scope.producer,
                    scope.tenant,
                    scope.institution,
                    request.requestId,
                    request.rtpId,
                    request.billID,
                    amount,
                    request.billDetails.currency,
                    scale,
                    dumps(payload),
                    scenario["outcome"] if scenario else "paid",
                    int(datetime.now(timezone.utc).timestamp()),
                ),
            )
            response = {
                "responseCode": "00",
                "responseDescription": "Accepted",
                "requestID": request.requestId,
                "rtpId": request.rtpId,
                "transferRequestId": transfer_id,
            }
            self.remember(db, scope, "collection", request.requestId, digest, response)
            return response

    def collection_status(self, scope, transfer_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM collection_requests LEFT JOIN collection_payments USING(transfer_id) "
                "WHERE transfer_id=? AND producer=? AND tenant=? AND biller=?",
                (transfer_id, scope.producer, scope.tenant, scope.institution),
            ).fetchone()
        if row is None:
            raise not_found()
        request_status, payment_status = "PND", "PENDING"
        if row["stage"] > 0 and row["outcome"] == "paid":
            request_status = "COM"  # RTP completed is still not evidence of payment.
        if row["stage"] == 2:
            request_status, payment_status = {
                "paid": ("COM", "PAID"),
                "failed": ("RJC", "FAILED"),
                "expired": ("EXP", "EXPIRED"),
            }[row["outcome"]]
        response = {
            "transferRequestId": transfer_id,
            "RequestId": row["request_id"],
            "rtpId": row["rtp_id"],
            "billId": row["bill_id"],
            "amount": Decimal(row["amount_minor"]).scaleb(-row["scale"]),
            "currency": row["currency"],
            "requestStatus": request_status,
            "paymentStatus": payment_status,
            "lastUpdateDate": row["last_update"],
        }
        if payment_status == "PAID":
            response["PaymentReferenceID"] = row["reference"]
        elif payment_status == "FAILED":
            response["failureReason"] = "payer-rejected"
        elif payment_status == "EXPIRED":
            response["failureReason"] = "request-expired"
        return response

    def collection_scenario(self, producer, tenant, biller, outcome):
        with self.connection(write=True) as db:
            db.execute(
                "INSERT INTO collection_scenarios VALUES (?, ?, ?, ?) "
                "ON CONFLICT(producer, tenant, biller) DO UPDATE SET outcome=excluded.outcome",
                (producer, tenant, biller, outcome),
            )

    def advance_collections(self, db):
        rows = db.execute("SELECT * FROM collection_requests WHERE stage < 2").fetchall()
        for row in rows:
            updated = int(datetime.now(timezone.utc).timestamp())
            if row["stage"] == 1 and row["outcome"] == "paid":
                db.execute(
                    "INSERT INTO collection_payments VALUES (?, ?, ?)",
                    (row["transfer_id"], "SIM-" + uuid4().hex[:16], updated),
                )
            db.execute(
                "UPDATE collection_requests SET stage=stage+1, last_update=? WHERE transfer_id=?",
                (updated, row["transfer_id"]),
            )

    def inspect_collections(self, transfer_id=None):
        condition, args = ("WHERE transfer_id=?", (transfer_id,)) if transfer_id else ("", ())
        with self.connection() as db:
            count = db.execute(
                f"SELECT count(*) FROM collection_requests {condition}",
                args,
            ).fetchone()[0]
            rows = db.execute(
                "SELECT * FROM collection_requests JOIN collection_payments USING(transfer_id) "
                f"{condition} ORDER BY request_id",
                args,
            ).fetchall()
        return {
            "requestCount": count,
            "payments": [
                {
                    "transferRequestId": row["transfer_id"],
                    "RequestId": row["request_id"],
                    "rtpId": row["rtp_id"],
                    "billId": row["bill_id"],
                    "billerId": row["biller"],
                    "PaymentReferenceID": row["reference"],
                    "amount": Decimal(row["amount_minor"]).scaleb(-row["scale"]),
                    "currency": row["currency"],
                }
                for row in rows
            ],
        }

    def inspect(self, batch_id=None):
        with self.connection() as db:
            condition, args = ("WHERE batch_id=?", (batch_id,)) if batch_id else ("", ())
            count = db.execute(f"SELECT count(*) FROM batches {condition}", args).fetchone()[0]
            rows = db.execute(
                "SELECT * FROM instructions JOIN credits USING(transaction_id) "
                f"{condition} ORDER BY request_id",
                args,
            ).fetchall()
        return {
            "batchCount": count,
            "credits": [
                {
                    "batchId": row["batch_id"],
                    "requestId": row["request_id"],
                    "transactionId": row["transaction_id"],
                    "financialAddress": row["address"],
                    "amount": Decimal(row["amount_minor"]).scaleb(-row["scale"]),
                    "currency": row["currency"],
                }
                for row in rows
            ],
        }
