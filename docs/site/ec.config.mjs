import { defineEcConfig } from '@astrojs/starlight/expressive-code';

// Expressive Code is configured here rather than through Starlight's
// `expressiveCode` option because the `starlight-openapi` plugin replaces that
// option wholesale: its `config:setup` hook builds a fresh object, reads
// `expressiveCode` off that empty object instead of off the user config, and
// hands `{ removeUnusedThemes: false }` to `updateConfig`, which shallow-merges
// it over the real settings. A config file is merged separately by
// astro-expressive-code and survives.
export default defineEcConfig({
  shiki: {
    // Shiki ships no Rhai grammar, so every Rhai block rendered as flat
    // unhighlighted text beside fully coloured YAML and shell blocks on the
    // same page, which reads as a broken code block. Rhai borrows Rust's
    // surface syntax (`fn`, `let`, `//`, the same string and number literals),
    // so the Rust grammar colours it correctly; only the `#{ }` map literal
    // falls back to plain text.
    langAlias: { rhai: 'rust' },
  },
});
