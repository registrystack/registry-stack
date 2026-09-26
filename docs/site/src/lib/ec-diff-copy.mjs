// Expressive Code plugin: the copy button of a diff block copies the lines as
// they read after the change, the unchanged and added lines, rather than the
// removed and added lines together. A reader who copies an edit gets text to
// paste into the file.
//
// A diff block is one written as `diff`, or as `diff lang="..."`, which the
// text markers plugin renders in that language with `useDiffSyntax` set.
// The text markers plugin has already stripped each line's `-` or `+` and
// marked the line, so a removed line is one carrying a whole-line `del`
// marker. A real diff file (with `---`, `+++`, or `@@` headers) carries no
// markers and copies unchanged. The frames plugin builds the copy button
// before this plugin runs, because Expressive Code runs its default plugins
// first; this plugin only rewrites the button's `data-code`.

function isRemoved(line) {
  return line.getAnnotations().some((annotation) => annotation.markerType === 'del' && !annotation.inlineRange);
}

function findCopyButton(node) {
  if (node.type === 'element' && node.tagName === 'button' && node.properties?.dataCode !== undefined) return node;
  for (const child of node.children ?? []) {
    const found = findCopyButton(child);
    if (found) return found;
  }
  return undefined;
}

export function pluginDiffCopy() {
  return {
    name: 'diff-copy',
    hooks: {
      postprocessRenderedBlock: ({ codeBlock, renderData }) => {
        if (codeBlock.language !== 'diff' && !codeBlock.props.useDiffSyntax) return;
        const button = findCopyButton(renderData.blockAst);
        if (!button) return;
        const kept = codeBlock.getLines().filter((line) => !isRemoved(line));
        // The frames plugin separates lines with DEL, which its copy script
        // turns back into newlines.
        button.properties.dataCode = kept.map((line) => line.text).join('\x7F');
      },
    },
  };
}
