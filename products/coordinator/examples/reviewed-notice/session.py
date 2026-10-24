#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Own the local services used by the reviewed-notice tutorial."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import re
import shlex
import subprocess
import sys
import time
import uuid


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SCRIPTS = REPO / "products/coordinator/scripts"
STATE = "session.json"


def load_fixture():
    sys.path.insert(0, str(SCRIPTS))
    path = SCRIPTS / "test-real-services.py"
    spec = importlib.util.spec_from_file_location("coordinator_real_services", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def read_state(session_dir):
    path = session_dir / STATE
    if not path.is_file():
        raise SystemExit(f"no reviewed-notice session at {session_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def checkpoint_cleanup(state_path, journey, **updates):
    current = {"supervisorPid": os.getpid()}
    if state_path.exists():
        current.update(json.loads(state_path.read_text(encoding="utf-8")))
    current.update({
        "cleanupStatus": "pending",
        "ownedBinDir": str(journey.bin),
        "ownedContainers": list(journey.containers),
        "ownedSessions": [
            {"tool": tool, "project": str(project)} for tool, project in journey.sessions
        ],
    })
    current.update(updates)
    write_private(state_path, current)


def retry_cleanup(session_dir, state):
    failures = []
    bin_dir = Path(state.get("ownedBinDir", ""))
    sessions = state.get("ownedSessions", [])
    containers = state.get("ownedContainers", [])
    if not isinstance(sessions, list) or not isinstance(containers, list):
        raise SystemExit("the reviewed-notice cleanup journal is invalid")
    for owned in reversed(sessions):
        if not isinstance(owned, dict) or owned.get("tool") not in ("bregctl", "caseworkctl"):
            failures.append("invalid session ownership")
            continue
        project = Path(owned.get("project", ""))
        marker = project / (".breg/dev/state.json" if owned["tool"] == "bregctl"
                            else ".casework/dev/state.json")
        if not marker.is_file():
            continue
        result = subprocess.run(
            [str(bin_dir / owned["tool"]), "--format", "json", "dev", "stop", str(project), "--remove"],
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            failures.append(owned["tool"])
    for container in reversed(containers):
        if not isinstance(container, str) or not container or len(container) > 128:
            failures.append("invalid container ownership")
            continue
        inspect = subprocess.run(
            ["docker", "container", "inspect", "--format",
             '{{ index .Config.Labels "org.registrystack.journey" }}', container],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if inspect.returncode != 0:
            listing = subprocess.run(
                ["docker", "container", "ls", "--all", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if listing.returncode == 0 and container not in listing.stdout.splitlines():
                continue
            failures.append("docker container " + container)
            continue
        if inspect.stdout.strip() != "coordinator-real-services":
            failures.append("unowned docker container " + container)
            continue
        removed = subprocess.run(
            ["docker", "rm", "--force", "--volumes", container],
            capture_output=True,
            timeout=60,
        )
        if removed.returncode != 0:
            failures.append("docker container " + container)
    if failures:
        state.update(cleanupStatus="failed", cleanupError="; ".join(failures))
        write_private(session_dir / STATE, state)
        raise SystemExit("reviewed-notice cleanup is incomplete; inspect its private session state")
    state.update(cleanupStatus="complete")
    state.pop("cleanupError", None)
    write_private(session_dir / STATE, state)
    done = session_dir / "control/stop.done"
    done.parent.mkdir(mode=0o700, exist_ok=True)
    done.touch(mode=0o600)


def start(args):
    session_dir = args.session_dir.resolve()
    state_path = session_dir / STATE
    if args.messaging_image and not re.fullmatch(r"ghcr\.io/registrystack/messaging@sha256:[0-9a-f]{64}", args.messaging_image):
        raise SystemExit("Messaging image must use its exact published GHCR digest")
    if state_path.exists():
        state = read_state(session_dir)
        if alive(state["supervisorPid"]):
            raise SystemExit(f"a reviewed-notice session already runs at {session_dir}")
        raise SystemExit(f"remove the stopped session directory before starting again: {session_dir}")
    session_dir.mkdir(parents=True, mode=0o700)
    log = (session_dir / "supervisor.log").open("ab")
    command = [sys.executable, str(Path(__file__).resolve()), "_serve",
               "--session-dir", str(session_dir), "--bin-dir", str(args.bin_dir.resolve())]
    if args.released_clients:
        command.append("--released-clients")
    if args.messaging_image:
        command.extend(("--messaging-image", args.messaging_image))
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True, close_fds=True)
    log.close()
    write_private(state_path, {"status": "starting", "supervisorPid": child.pid})
    deadline = time.monotonic() + args.start_timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            state = read_state(session_dir)
            raise SystemExit(f"reviewed-notice session failed: {state.get('error', 'inspect supervisor.log')}")
        state = read_state(session_dir)
        if state["status"] == "ready":
            print(json.dumps(state, indent=2))
            return
        if state["status"] == "failed":
            raise SystemExit(f"reviewed-notice session failed: {state['error']}")
        time.sleep(0.2)
    raise SystemExit(f"reviewed-notice session did not become ready within {args.start_timeout} seconds")


def status(args):
    state = read_state(args.session_dir.resolve())
    state["supervisorRunning"] = alive(state["supervisorPid"])
    print(json.dumps(state, indent=2))


def signal_command(args, name):
    session_dir = args.session_dir.resolve()
    state = read_state(session_dir)
    if not alive(state["supervisorPid"]):
        if name == "stop" and state.get("cleanupStatus") == "complete":
            return
        if name == "stop":
            retry_cleanup(session_dir, state)
            return
        raise SystemExit("the reviewed-notice supervisor is not running")
    control = session_dir / "control"
    control.mkdir(mode=0o700, exist_ok=True)
    request = control / f"{name}.request"
    done = control / f"{name}.done"
    done.unlink(missing_ok=True)
    request.touch(mode=0o600)
    deadline = time.monotonic() + args.command_timeout
    while time.monotonic() < deadline:
        if done.exists():
            if name == "restart":
                status(args)
            return
        if not alive(state["supervisorPid"]):
            if name == "stop":
                latest = read_state(session_dir)
                if latest.get("cleanupStatus") != "complete":
                    retry_cleanup(session_dir, latest)
                return
            raise SystemExit("the reviewed-notice supervisor stopped before completing the command")
        time.sleep(0.2)
    raise SystemExit(f"the reviewed-notice supervisor did not complete {name} in time")


def messaging_image_tools(journey, image):
    """Run the released Linux Messaging pair beside native local products."""
    if not re.fullmatch(r"ghcr\.io/registrystack/messaging@sha256:[0-9a-f]{64}", image):
        raise ValueError("Messaging image must use its exact published GHCR digest")
    for tool in ("messaging", "messagingctl"):
        name = "coordinator-tutorial-" + tool + "-" + uuid.uuid4().hex[:12]
        command = ["docker", "run", "--rm", "--platform", "linux/amd64", "--name", name,
                   "--label", "org.registrystack.journey=coordinator-real-services",
                   "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--mount", f"type=bind,source={journey.root},target={journey.root}",
                   "--entrypoint", "/usr/local/bin/" + tool, image]
        path = journey.bin / tool
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\nexec " + shlex.join(command) + ' "$@"\n')
        path.chmod(0o700)
        journey.containers.append(name)


def serve(args):
    fixture = load_fixture()
    session_dir = args.session_dir.resolve()
    state_path = session_dir / STATE
    os.umask(0o077)
    journey = None
    succeeded = False
    try:
        owned = session_dir / "owned"
        owned.mkdir(mode=0o700)
        journey_type = fixture.Journey
        if args.released_clients:
            from released_client import prepare_input, start_run

            class ClientJourney(fixture.Journey):
                def reviewed_notice_input(self, owner, application):
                    report = self.ctl("bregctl", "dev", "token", "application-reader", owner)
                    return prepare_input(self.urls["breg"], report["headerFile"], application)

                def start(self, owner, url, label, data, flow="deferred-appointment"):
                    token = self.token("bregctl", owner, "coordinator-producer")
                    return start_run(url, token, flow, label, data)

            journey_type = ClientJourney
        binaries = ["breg", "bregctl", "casework", "caseworkctl", "coordinator", "coordinatorctl"]
        if not args.messaging_image:
            binaries.extend(("messaging", "messagingctl"))
        journey = journey_type(owned, args.bin_dir.resolve(), 2,
            require_reviewed_notice_starter=not args.released_clients, required_binaries=binaries)
        if args.messaging_image:
            messaging_image_tools(journey, args.messaging_image)
        checkpoint_cleanup(state_path, journey, status="starting")
        coordinator_database, _ = journey.tls_database("coordinator-database", superuser=True)
        messaging_database, messaging_database_root = journey.tls_database("messaging-database")
        checkpoint_cleanup(state_path, journey)
        journey.env["COORDINATOR_TEST_DATABASE_URL"] = coordinator_database
        journey.env["COORDINATOR_MESSAGING_TEST_DATABASE_URL"] = messaging_database
        os.environ["COORDINATOR_TEST_DATABASE_URL"] = coordinator_database
        os.environ["COORDINATOR_MESSAGING_TEST_DATABASE_URL"] = messaging_database

        owner = fixture.write_breg(journey.root / "breg", journey.urls)
        journey.ctl("bregctl", "check", owner)
        journey.sessions.append(("bregctl", owner))
        checkpoint_cleanup(state_path, journey)
        breg_report = journey.ctl("bregctl", "dev", "start", owner,
            "--breg-port", journey.ports["breg"], "--issuer-port", journey.ports["issuer"],
            "--database-port", journey.ports["bregdb"], "--breg-bin", journey.bin / "breg")
        resource = breg_report.get("resource", breg_report.get("audience"))
        messaging_url, messaging_runtime = journey.messaging_service(
            owner, test_only_plaintext=False,
            trusted_root_certificate=messaging_database_root,
        )
        checkpoint_cleanup(state_path, journey)

        coordinator_port, casework_port = fixture.free_ports(2)
        completion_token = secrets.token_urlsafe(32)
        receiver = f"http://127.0.0.1:{coordinator_port}/v1/review-completions"
        casework_url = journey.review_casework(owner, resource, casework_port, receiver, completion_token)
        checkpoint_cleanup(state_path, journey)
        keys = journey.root / "coordinator-review-secrets"
        reviewer = journey.export(owner, "review-producer", keys)
        reader = journey.export(owner, "application-reader", keys)
        sender = journey.export(owner, "case-system", keys)
        fixture.private(keys / "review-completion-token", completion_token)
        runtime, coordinator_url, coordinator = journey.coordinator_service("reviewed-notice", keys, {
            "applications": {"type": "breg", "baseUrl": journey.urls["breg"],
                "profile": "follow-up-reader",
                "authorization": journey.authorization(reader, resource, ["records:get"])},
            "review": {"type": "casework-review-producer", "baseUrl": casework_url,
                "profile": "coordinator-producer", "producer": "coordinator",
                "authorization": journey.authorization(reviewer, resource, ["casework:review"]),
                "completion": {"recipientBinding": "coordinator-v1",
                    "bearerTokenRef": "secret:file/review-completion-token"},
                "resultCheckSeconds": 900},
            "notices": {"type": "messaging", "baseUrl": messaging_url,
                "authorization": journey.authorization(sender, sender["resource"], ["messaging:send"])},
        }, coordinator_port, "coordinator-reviewed-notice-tutorial")

        seed = journey.token("bregctl", owner, "seed-client")
        application = fixture.http("POST", journey.urls["breg"] + "/v1/records/applications?accessProfile=seeder",
            seed, {"data": {"tenant": "tenant-a", "applicantName": "Amina Example",
                "benefitProgram": "housing-support", "requestedAmount": 1200,
                "email": "amina@example.invalid", "noticeAllowed": True,
                "appointmentAllowed": True}}, {"Idempotency-Key": str(uuid.uuid4())}, (201,))
        application_id = application["data"]["recordIdentifier"]
        prepared = journey.reviewed_notice_input(owner, application_id)
        run_id = journey.start(owner, coordinator_url, "tutorial-reviewed-notice", prepared, "reviewed-notice")
        deadline = time.monotonic() + 60
        while (run := journey.inspect(owner, coordinator_url, run_id)["run"])["step"] != "await-review":
            assert run["state"] == "running", f"run stopped at {run['step']}: {run['failureCode']}"
            assert time.monotonic() < deadline, "run did not reach its review wait"
            time.sleep(0.2)
        staff_header = Path(journey.ctl("bregctl", "dev", "token", "staff", owner)["headerFile"])
        producer_header = Path(journey.ctl("bregctl", "dev", "token", "coordinator-producer", owner)["headerFile"])
        state = {
            "status": "ready", "supervisorPid": os.getpid(), "coordinatorRestarts": 0,
            "cleanupStatus": "pending",
            "applicationId": application_id, "runId": run_id,
            "workflow": run["workflow"], "workflowRevision": run["workflowRevision"],
            "bregApi": journey.urls["breg"], "caseworkApi": casework_url,
            "coordinatorApi": coordinator_url, "mailpit": journey.mailpit_url,
            "caseworkProfile": "staff", "staffHeaderFile": str(staff_header),
            "coordinatorHeaderFile": str(producer_header), "ownerProject": str(owner),
            "messagingRuntime": str(messaging_runtime),
        }
        checkpoint_cleanup(state_path, journey, **state)
        control = session_dir / "control"
        control.mkdir(mode=0o700, exist_ok=True)
        while True:
            if (control / "stop.request").exists():
                break
            if (control / "restart.request").exists():
                journey.stop(coordinator)
                coordinator = journey.spawn("coordinator", runtime, "coordinator-reviewed-notice-tutorial-restarted")
                journey.ready(coordinator, coordinator_url)
                state["coordinatorRestarts"] += 1
                checkpoint_cleanup(state_path, journey,
                                   coordinatorRestarts=state["coordinatorRestarts"])
                (control / "restart.request").unlink(missing_ok=True)
                (control / "restart.done").touch(mode=0o600)
            time.sleep(0.2)
        succeeded = True
    except Exception as error:
        current = {"supervisorPid": os.getpid()}
        if state_path.exists():
            current.update(json.loads(state_path.read_text(encoding="utf-8")))
        current.update(status="failed", error=f"{type(error).__name__}: {error}")
        write_private(state_path, current)
    finally:
        if journey is not None:
            checkpoint_cleanup(state_path, journey)
            try:
                journey.cleanup(True)
            except Exception as error:
                current = read_state(session_dir)
                current.update(cleanupStatus="failed", cleanupError=f"{type(error).__name__}: {error}")
                write_private(state_path, current)
            else:
                current = read_state(session_dir)
                current.update(cleanupStatus="complete")
                current.pop("cleanupError", None)
                if succeeded:
                    current["status"] = "stopped"
                write_private(state_path, current)
                done = session_dir / "control/stop.done"
                done.parent.mkdir(mode=0o700, exist_ok=True)
                done.touch(mode=0o600)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("start", "status", "restart-coordinator", "stop", "_serve"):
        command = sub.add_parser(name)
        command.add_argument("--session-dir", type=Path, default=Path("tutorial-work/reviewed-notice"))
        if name in ("start", "_serve"):
            command.add_argument("--bin-dir", type=Path,
                                 default=Path(os.environ.get("COORDINATOR_TUTORIAL_BIN_DIR", REPO / "target/debug")))
            command.add_argument("--messaging-image", help="exact published Messaging image digest; requires Docker host networking")
            command.add_argument("--released-clients", action="store_true",
                                 help="use the installed unified client instead of a Rust input helper")
        if name == "start":
            command.add_argument("--start-timeout", type=int, default=240)
        if name in ("restart-coordinator", "stop"):
            command.add_argument("--command-timeout", type=int, default=60)
    return result


def main():
    args = parser().parse_args()
    if args.command == "start":
        start(args)
    elif args.command == "status":
        status(args)
    elif args.command == "restart-coordinator":
        signal_command(args, "restart")
    elif args.command == "stop":
        signal_command(args, "stop")
    else:
        serve(args)


if __name__ == "__main__":
    main()
