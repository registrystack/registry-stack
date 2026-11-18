# SPDX-License-Identifier: Apache-2.0

"""Exercise operator purge and restart on the disposable native fixture."""

import json
import re
import subprocess

import fixture_path
fixture_path.ensure_importable()
from journey import JourneyError, expect, records

PROJECTION = "holdings-indexed"
VIEW = "business-holdings-indexed"
LINK = "holdings"
OPERATION = "holdings-by-business"


def operator_report(output, action):
    try:
        report = json.loads(output)
    except ValueError as error:
        raise JourneyError("the operator returned an invalid scope report") from error
    expect(isinstance(report, dict) and report.get("ok") is True
           and report.get("command") == f"external-projection {action}"
           and isinstance(report.get("scope"), dict),
           "the operator did not return one successful scope report")
    return report["scope"]


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
    def __init__(self, journey, fixture, work, facts, ctl, runtime, write_json):
        self.journey = journey
        self.fixture = fixture
        self.work = work
        self.ctl = ctl
        self.runtime = runtime
        self.write_json = write_json
        self.fact = next(fact for fact in facts["projections"] if fact["id"] == PROJECTION)

    def operator(self, action, step, current=None):
        with (self.work / f"scope-{step}.stderr").open("xb") as error:
            result = subprocess.run(
                [*self.ctl, "external-projection", action, "--runtime-config", self.runtime,
                 "--projection", PROJECTION],
                cwd=self.work, stdout=subprocess.PIPE, stderr=error, timeout=60, check=False,
            )
        expect(result.returncode == 0, "the migration-only scope operator failed; see the owner-only fixture log")
        report = operator_report(result.stdout, action)
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

    def purge(self):
        self.journey.control("reset")
        # The journey ends on an empty holdings snapshot; the sweep interval is an hour, so ask
        # for the business root's refresh to republish the reset fixture's two holdings.
        self.journey.refresh_until(VIEW, LINK, self.journey.args.business_root,
                                   lambda: len(self.journey.rows(self.journey.business()) or []) == 2,
                                   "a refresh to republish the reset holdings snapshot")
        verify_holdings(self.journey)
        active = self.operator("inspect", "before-purge")
        expect(active["active"] and active["snapshotCounts"]["fresh"] > 0,
               "purge fixture lacked a retained holdings snapshot")
        before = self.journey.source_calls()
        self.journey.control("hold-next", operation=OPERATION)
        # The staff application request queues a refresh; the worker's next tick acquires and stops at the barrier.
        self.journey.request_refresh(VIEW, LINK, self.journey.args.business_root)
        expect(self.fixture.wait_for_hold(timeout=self.journey.args.refresh_timeout),
               "the first holdings page did not reach the source barrier")
        held = self.journey.source_calls()
        expect(held == {**before, OPERATION: before.get(OPERATION, 0) + 1},
               "the source received more than the first holdings request before the purge")
        try:
            purged = self.operator("purge", "purge", active)
            expect(not purged["active"] and purged["epoch"] == active["epoch"],
                   "the operator did not end the inspected scope")
        finally:
            self.journey.control("release")
        verify_hidden(self.journey)
        after = self.operator("inspect", "after-purge")
        expect(not after["active"] and after["epoch"] == purged["epoch"]
               and after["snapshotCounts"] == {"fresh": 0, "expired": 0, "invalidated": 0},
               "the purge did not delete the retained holdings snapshots")
        self.write_json(self.work / "recovery-inflight.json", {
            "sourceRequestsBefore": before, "sourceRequestsAtPurge": held,
            "sourceRequestsAfterRelease": self.journey.source_calls(),
        })
        self.purged_epoch = purged["epoch"]
        self.calls_at_purge = self.journey.source_calls()

    def verify_rebuild(self):
        # The restarted worker finds a scope without snapshots and sweeps it at once.
        self.journey.wait_until(lambda: len(self.journey.rows(self.journey.business()) or []) == 2,
                                "the restarted worker to rebuild the holdings snapshot")
        rebuilt = self.operator("inspect", "after-restart")
        expect(rebuilt["active"] and rebuilt["epoch"] != self.purged_epoch
               and rebuilt["snapshotCounts"]["fresh"] > 0
               and rebuilt["bindingDigest"] == self.fact["bindingDigest"]
               and rebuilt["grantDigest"] == self.fact["grantDigest"]
               and rebuilt["cacheTtlSeconds"] == self.fact["cacheTtlSeconds"],
               "the restart did not bind a fresh scope for the current reviewed binding")
        after_rebuild = self.journey.source_calls()
        expect(after_rebuild.get(OPERATION, 0) >= self.calls_at_purge.get(OPERATION, 0) + 2,
               "rebuilding the scope did not acquire both holdings pages")
        verify_holdings(self.journey)
        expect(self.journey.source_calls() == after_rebuild, "the rebuilt indexed read attempted acquisition")
        self.write_json(self.work / "recovery-rebuild.json", {
            "sourceRequestsAtPurge": self.calls_at_purge, "sourceRequestsAfterRebuild": after_rebuild,
        })
