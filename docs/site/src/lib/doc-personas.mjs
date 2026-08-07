// The deployment roles a tutorial can be written for, defined for readers in
// start/when-to-use.mdx under "Who does what". A tutorial declares one or more
// of these in its `persona` frontmatter key so a reader can tell at a glance
// whether the page is theirs.
//
// This is a different axis from the `audience` key, which names who reads a
// specification (integrator, maintainer, specification editor, tooling) and is
// defined normatively in spec/RS-TERMS Section 6. Keep the two vocabularies
// apart: one describes a role in a deployment, the other a role in the reading
// of a specification.
export const DOC_PERSONAS = [
  'assertion provider',
  'data publisher',
  'consumer or verifier',
  'operator',
];
