# Contributing to lockscan

Thank you for your interest in contributing! Bug reports, feature requests, and pull requests are all welcome.

## Code of conduct

This project follows a simple rule: be respectful. Constructive criticism is great; personal attacks, harassment, or exclusionary language are not. If something feels off, open an issue or reach out privately.

## Development setup

```bash
pnpm install
pnpm test          # run tests with Vitest
pnpm run check     # check with Biome
pnpm run check:fix # auto-fix Biome issues
pnpm run build     # compile TypeScript with tsup
pnpm run typecheck # tsc --noEmit
```

The pre-commit hook (Husky) runs `biome check` and rebuilds `dist/` automatically — this keeps both the CLI output and `dist/action.cjs` (the compiled GitHub Action) in sync with the TypeScript sources.

## Adding a new ecosystem

1. Create `src/ecosystems/<name>/index.ts` implementing the `EcosystemAnalyzer` interface
2. Register it in `src/ecosystems/index.ts`
3. Add fixtures under `tests/fixtures/<name>/`
4. Add tests under `tests/ecosystems/<name>/`

If the ecosystem also needs GitHub Action annotations, add a `ManifestResolver` for it in `src/github/annotations.ts` via `registerManifestResolver`.

## Submitting changes

- Keep pull requests focused — one feature or fix per PR.
- Make sure `pnpm test` and `pnpm run check` both pass before opening a PR.
- Describe *why* the change is needed, not just what it does.
