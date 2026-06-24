# portal - Glass Government Citizen Services Portal

This is the Phase 0 mock of the Glass Government citizen services portal for the Republic of Solmara (a fictional nation). It demonstrates the "evidence field" UX pattern: structured, authority-verified fields that show the citizen exactly what data was checked, which authority answered, and what was NOT disclosed. All authority calls are behind the `EvidenceProvider` seam (see `src/lib/providers/EvidenceProvider.ts`), which starts with a `MockEvidenceProvider` and will be wired to live Registry Notary endpoints in Phase 1 without a rewrite.

## Source-of-truth documentation

- Public implementation source: this portal package and the surrounding Lab docs in the monorepo.
- Private planning notes are intentionally not part of the public repository.

## Stack and commands

- SvelteKit 2 + Svelte 5 (runes mode), TypeScript strict, Vite, adapter-node
- `pnpm dev` - start dev server
- `pnpm build` - production build (adapter-node output in `build/`)
- `pnpm preview` - run the built server (for e2e and manual review)
- `pnpm check` - svelte-check typecheck; must report 0 errors before any PR
- `pnpm test` - Vitest unit tests; must be green
- `pnpm e2e` - Playwright end-to-end tests; must be green

## Conventions

- **Svelte 5 runes only.** Use `$state`, `$derived`, `$props`, `$effect`. No legacy reactive syntax (`$:`, `export let`).
- **TypeScript strict.** No `any`, no type assertions without a comment, no `@ts-ignore`.
- **Plain CSS with design tokens.** No Tailwind, no CSS-in-JS. Use variables from `src/lib/design/tokens.css`. Component styles are scoped (inside `<style>` blocks).
- **Co-locate tests.** Unit tests live as `*.test.ts` next to the source file they test (e.g. `Foo.svelte` and `Foo.test.ts` in the same directory). TDD the renderer.
- **No em dashes anywhere** in copy, code comments, or documentation. Use commas, colons, semicolons, or parentheses instead. This is a project-wide style rule.
- **Never log or echo secrets.** Redact at the boundary before any value reaches stdout, a file, or a network call.
- **Channel colours are load-bearing.** Always pair colour with an icon AND text label. Never use colour as the only signal (accessibility requirement).
- **The synthetic-data banner is always visible.** Do not hide it, overlay it, or conditionally render it. Exact text: `Synthetic demo data · Republic of Solmara is a fictional nation.`
- **Field-facing wait copy always names the authority.** Never show a bare "Loading..." to the user. Always say which authority is being contacted (e.g. "Contacting Civil Registry...").

## Hard rules

- `src/lib/types.ts` and `src/lib/providers/EvidenceProvider.ts` are SHARED contracts. Changes must be additive only. Coordinate via the manager before modifying either file.
- Mock data lives in `src/lib/providers/mock/`. The mock implements `EvidenceProvider` exactly. The live provider will swap in without touching the renderer.
- BFF endpoints (SSE, evaluate, auth) live in `src/lib/server/` and the corresponding routes. Keep server-only code out of `$lib` files that are imported client-side.

## Directory ownership (parallel agents must not collide on the same files)

| Directory / Route | Owner agent |
|---|---|
| `src/lib/fields/**`, `src/routes/_gallery/**` | EvidenceField renderer agent |
| `src/lib/providers/**`, `src/lib/server/**`, routes `/proof/stream`, `/api/evaluate`, `/auth/*` | Mock provider + BFF agent |
| `src/lib/proof/**` | Proof inspector + ticker agent |
| `src/lib/rail/**` | Ministry rail agent |
| `src/lib/forms/**`, routes for `/`, `/services/[slug]`, `+layout.svelte` wiring | Forms + flows agent |
| `src/lib/types.ts`, `src/lib/providers/EvidenceProvider.ts` | SHARED: additive changes only, coordinate via manager |
| `src/lib/design/tokens.css`, `src/app.css`, `AGENTS.md` | Foundation (this layer); changes require manager review |
