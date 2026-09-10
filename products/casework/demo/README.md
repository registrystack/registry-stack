# First Casework technical checkpoint demo

Run the complete professional-registry review journey with a matching Registry
App Kit checkout. Install Docker, Rust, Node.js and Python 3, and use the pnpm
version declared by that App Kit project's `packageManager` field. Before the
first run, install the kit's locked dependencies and Chromium from its `project`
directory:

```sh
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
```

Then run from the Stack checkout:

```sh
products/casework/demo/run.sh \
  --app-kit-worktree /path/to/registry-app-kit \
  --evidence-dir /path/outside/every/git-repository/casework-evidence
```

The Stack checkout containing `run.sh` is the candidate source. The selected App
Kit checkout must contain
`project/deployment/scripts/verify-casework-checkpoint.py`. Use fresh checkouts
at the intended source revisions. The command does not fetch or reset them.

The App Kit verifier owns service startup and the real authenticated host/API
journey. It also runs focused browser tests against controlled host responses.
It builds and installs the local candidate of the maintained client, runs the
applicable kit checks, and exercises Administrator setup, submission, claim, correction and
resubmission, approval, separate application, holdings, and accountability. It
also verifies restart and lost-response recovery. A successful startup alone is
not a successful checkpoint. Consult the verifier's result and logs in the
chosen evidence directory.

The automated measurements do not establish the value checkpoint, human
usability, or screen-reader acceptance. Run the planned human comparison and
validate the staff and applicant screens separately before making those claims.

The candidate client is built from source for this demo. An existing published
client version is not evidence that the new Casework facade is available. Keep
runtime state, generated credentials, and verification logs out of product
commits.

This demo stops at the first checkpoint. It does not implement the subsequent
standalone hosted workflow, absence cover, routing rules, calendar timers, bulk
decisions, or outbound delivery.
