# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and GitHub Copilot CLI when working in this repository.

nuclear-option is a TypeScript CLI and library that scans JavaScript and TypeScript projects for high-impact dependency, code-pattern and secret risks, scores them, and can fail a build above a threshold. It is published to npm as `nuclear-option`. The repository is public.

## Commands

```bash
npm run build                       # tsc, src/ -> dist/ (gitignored); the bin is dist/cli.js
npm test                            # jest via ts-jest, src/__tests__/**
npx jest src/__tests__/core/scoring.test.ts -t '<name>'
npm run lint                        # eslint src/**/*.ts
node dist/cli.js scan . --format text   # after a build
```

The CLI runs from `dist/`, so rebuild before trying a source change from the command line. `prepublishOnly` builds but does not run the tests.

## Structure

`src/core/scanner.ts` collects files and runs the three analyzers in `src/analyzers/` (dependency, code-pattern, secrets); `src/core/scoring.ts` turns findings into the vulnerability score that `--fail-threshold` compares against; `src/formatters/` renders JSON or text; `src/types.ts` holds the shared types and `src/index.ts` is the library export. `.nuclear-option.example.yml` documents the config file shape. `NUCLEAR_OPTION_IMPLEMENTATION.md` is the original plan, so check the code rather than trusting it for current behavior.

## Releasing

`files` limits the package to `dist/`, `README.md`, `LICENSE` and `package.json`. The README states the published version, so bump it with `package.json` and `CHANGELOG.md`. The release checklist is in `../README.md`.
