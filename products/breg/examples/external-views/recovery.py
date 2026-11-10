# SPDX-License-Identifier: Apache-2.0

"""Exercise operator withdrawal and restart on the disposable native fixture."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

from journey import JourneyError, expect, records, request

PROJECTION = "holdings-indexed"
VIEW = "business-holdings-indexed"
LINK = "holdings"
OPERATION = "holdings-by-business"
OPERATOR = Path(__file__).resolve().parents[4] / "scripts/external-projection-scope.sh"


def operator_report(output):
    lines = [line.strip().removesuffix("+").rstrip() for line in output.decode().splitlines()]
    expect(lines.count("{") == lines.count("}") == lines.count("COMMIT") == 1
           and "(1 row)" in lines, "the operator did not return one committed scope report")
    try:
        report = json.loads("\n".join(lines[lines.index("{"):lines.index("}") + 1]))
    except ValueError as error:
        raise JourneyError("the operator returned an invalid scope report") from error
    expect(isinstance(report, dict), "the operator returned an invalid scope report")
    return report


def verify_hidden(journey):
    before = journey.source_calls()
    status, body = journey.business()
    expect(status == 200 and isinstance(body, dict) and body.get("status") == "unavailable"
           and records((status, body)) == [],
           "the holdings detail disclosed data without a complete current scope")
    status, body = journey.view(VIEW, LINK, journey.args.business_root, query={"$count": "true"})
    expect(status == 503 and isinstance(body, dict),
           "the holdings count accepted incomplete indexed coverage")
    expect(journey.source_calls() == before, "serving incomplete holdings attempted acquisition")


def verify_holdings(journey):
    rows = records(journey.business())
    expect(len(rows) == 2 and {row["fields"]["shareholder-type"] for row in rows} == {"person", "business"},
           "the fixture did not have a complete two-page holdings snapshot")


class ScopeRecovery:
    def __init__(self, journey, fixture, work, facts, private_write, write_json):
        self.journey = journey
        self.fixture = fixture
        self.work = work
        self.write_json = write_json
        self.fact = next(fact for fact in facts["projections"] if fact["id"] == PROJECTION)
        keys = work / "secrets"
        # The launcher validates these as loopback, split-role fixture URLs before staging them.
        target = urlsplit((keys / "migration-url").read_text(encoding="ascii"))
        service = keys / "recovery-pg-service.conf"
        private_write(service, (
            f"[external-fixture-migration]\nhost={target.hostname}\nport={target.port}\n"
            f"dbname={target.path[1:]}\nuser={unquote(target.username)}\n"
        ).encode("ascii"))
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
        self.env.update(PGSERVICEFILE=str(service), PGSSLMODE="verify-full",
                        PGSSLROOTCERT=str(keys / "postgres-ca"), PGCONNECT_TIMEOUT="3",
                        PGPASSFILE="/dev/null", LC_ALL="C")
        if target.password is not None:
            self.env["PGPASSWORD"] = unquote(target.password)

    def operator(self, action, step, current=None, arguments=()):
        identity = () if current is None else (current["epoch"], current["packageDigest"], current["activationId"])
        with (self.work / f"scope-{step}.stderr").open("xb") as error:
            result = subprocess.run(
                ["bash", OPERATOR, action, "external-fixture-migration", PROJECTION, *identity, *arguments],
                cwd=self.work, env=self.env, stdout=subprocess.PIPE, stderr=error, timeout=20, check=False,
            )
        expect(result.returncode == 0, "the migration-only scope operator failed; see the owner-only fixture log")
        report = operator_report(result.stdout)
        expect(report.get("projection") == PROJECTION and type(report.get("active")) is bool
               and all(isinstance(report.get(key), str) for key in ("epoch", "packageDigest", "activationId"))
               and all(re.fullmatch(r"[0-9a-f-]{36}", report[key]) for key in ("epoch", "activationId"))
               and re.fullmatch(r"sha256:[0-9a-f]{64}", report["packageDigest"]),
               "the operator did not identify the activated fixture scope")
        if current is not None:
            expect(all(report[key] == current[key] for key in ("packageDigest", "activationId")),
                   "operator maintenance changed the package activation identity")
        self.write_json(self.work / f"scope-{step}.json", report)
        return report

    def withdraw_and_rotate(self):
        self.journey.control("reset")
        self.journey.refresh(VIEW, LINK)
        verify_holdings(self.journey)
        active = self.operator("inspect", "before-withdrawal")
        expect(active["active"] and active["snapshotCounts"]["fresh"] > 0,
               "withdrawal fixture lacked a retained holdings snapshot")
        before = self.journey.source_calls()
        self.journey.control("hold-next", operation=OPERATION)
        with ThreadPoolExecutor(max_workers=1) as workers:
            inflight = workers.submit(
                request, self.journey.args.breg_origin, f"/v1/external-views/{VIEW}/{LINK}/refresh",
                self.journey.auth["projection-refresh"], method="POST",
                query={"accessProfile": "projection-refresh"},
            )
            try:
                expect(self.fixture.wait_for_hold(timeout=2), "the first holdings page did not reach the source barrier")
                held = self.journey.source_calls()
                expect(held == {**before, OPERATION: before.get(OPERATION, 0) + 1},
                       "the source received more than the first holdings request before withdrawal")
                withdrawn = self.operator("withdraw", "withdrawal", active)
                expect(not withdrawn["active"] and withdrawn["epoch"] == active["epoch"],
                       "the operator did not withdraw the inspected scope")
                expect(self.fixture.status()["held"], "scope withdrawal exceeded the source barrier deadline")
            finally:
                self.journey.control("release")
            status, body = inflight.result(timeout=8)
        expect(self.journey.source_calls() == held, "a subsequent Adapter request followed scope withdrawal")
        expect(status == 503 or (status == 200 and body["published"] == 0 and body["unavailable"] > 0),
               "the in-flight refresh did not fail closed after withdrawal")
        verify_hidden(self.journey)
        inactive = self.operator("inspect", "after-withdrawal")
        expect(not inactive["active"] and inactive["epoch"] == withdrawn["epoch"]
               and inactive["snapshotCounts"] == {"fresh": 0, "expired": 0, "invalidated": 0},
               "withdrawal did not purge the retained holdings snapshots")
        self.write_json(self.work / "recovery-inflight.json", {
            "refreshStatus": status, "sourceRequestsBefore": before, "sourceRequestsAtWithdrawal": held,
            "sourceRequestsAfterRelease": self.journey.source_calls(),
        })
        self.rotate(inactive)

    def rotate(self, inactive):
        rotated = self.operator("rotate", "rotation", inactive, (
            self.fact["bindingDigest"], self.fact["grantDigest"],
            str(self.fact["cacheTtlSeconds"]), str(self.fact["maximumRetentionSeconds"]),
        ))
        expect(rotated["active"] and rotated["epoch"] != inactive["epoch"]
               and rotated["bindingDigest"] == self.fact["bindingDigest"]
               and rotated["grantDigest"] == self.fact["grantDigest"]
               and rotated["cacheTtlSeconds"] == self.fact["cacheTtlSeconds"]
               and rotated["retentionSeconds"] == self.fact["maximumRetentionSeconds"],
               "rotation did not install a fresh epoch for the current reviewed binding")
        self.calls_at_rotation = self.journey.source_calls()
        self.epoch = rotated["epoch"]

    def verify_rebuild(self):
        verify_hidden(self.journey)
        incomplete = self.operator("inspect", "after-restart")
        expect(incomplete["active"] and incomplete["epoch"] == self.epoch
               and incomplete["snapshotCounts"] == {"fresh": 0, "expired": 0, "invalidated": 0},
               "restart did not preserve the empty rotated holdings scope")
        expect(self.journey.source_calls() == self.calls_at_rotation,
               "the restarted candidate acquired holdings before an explicit refresh")
        result = self.journey.refresh(VIEW, LINK)
        expect(result["published"] > 0 and result["unavailable"] == 0,
               "the rotated scope did not publish a fresh holdings refresh")
        after_refresh = self.journey.source_calls()
        expect(after_refresh.get(OPERATION, 0) >= self.calls_at_rotation.get(OPERATION, 0) + 2,
               "rebuilding the scope did not acquire both holdings pages")
        verify_holdings(self.journey)
        expect(self.journey.source_calls() == after_refresh, "the rebuilt indexed read attempted acquisition")
        self.write_json(self.work / "recovery-rebuild.json", {
            "refresh": result, "sourceRequestsBeforeRefresh": self.calls_at_rotation,
            "sourceRequestsAfterRefresh": after_refresh,
        })
