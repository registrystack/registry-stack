import assert from 'node:assert/strict';
import test from 'node:test';

import { TOOLSETS } from './toolsets.mjs';

// A toolset's commands pattern decides which pages its gate must replay, so it
// matches a command a fence runs and not a path or file that shares its name.
const CASES = {
  breg: {
    runs: ['bregctl init .', 'bregctl dev start .', 'breg --version', 'version=$(bregctl --version)', 'bregctl dev stop .; echo done'],
    names: ['cd tutorial-work/breg', 'cat .breg/dev/state.json', 'ls ./breg', 'cat breg.yaml', 'cd breg-demo', 'ls breg/'],
  },
  casework: {
    runs: ['caseworkctl dev start .', 'casework --version', 'caseworkctl check . | tail -1'],
    names: ['cd tutorial-work/casework', 'cat .casework/dev/state.json', 'cat casework.yaml', 'ls casework/'],
  },
  evidence: {
    runs: ['evidencectl init .', 'evidence --version', 'evidence-oid4vci --help', 'products/evidence/scripts/check-contracts.sh'],
    names: ['cd ~/work/evidence', 'ls .evidence/clients', 'cat evidence.yaml', 'ls evidence/'],
  },
};

for (const [name, { runs, names }] of Object.entries(CASES)) {
  test(`the ${name} toolset matches the commands a fence runs, not paths that share their name`, () => {
    const { commands } = TOOLSETS[name];
    for (const code of runs) assert.equal(commands.test(code), true, `${name} must match: ${code}`);
    for (const code of names) assert.equal(commands.test(code), false, `${name} must not match: ${code}`);
  });
}
