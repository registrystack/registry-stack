import { authorizeCedar, cedarVersion, validateCedarArtifacts } from "./cedar.mjs";
import { authorizeClosedYaml } from "./closed-yaml.mjs";
import { scenarios } from "./scenarios.mjs";

const decisions = [];
for (const scenario of scenarios) {
  const cedar = await authorizeCedar(scenario.policy, scenario.input);
  const closedYaml = await authorizeClosedYaml(scenario.policy, scenario.input);
  decisions.push({
    scenario: scenario.id,
    policy: scenario.policy,
    expected: scenario.allowed,
    cedar: { allowed: cedar.allowed, reason: cedar.reason },
    closedYaml: { allowed: closedYaml.allowed, reason: closedYaml.reason },
  });
}

process.stdout.write(
  `${JSON.stringify(
    {
      synthetic: true,
      cedarVersion: cedarVersion(),
      cedarValidation: await validateCedarArtifacts(),
      decisions,
    },
    null,
    2,
  )}\n`,
);
