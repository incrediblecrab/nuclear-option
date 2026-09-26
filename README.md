# nuclear-option

![npm version](https://img.shields.io/npm/v/nuclear-option) ![MLoT](https://img.shields.io/badge/MLoT-ai-blue)

nuclear-option is a TypeScript CLI and library for scanning JavaScript and TypeScript projects for high-impact dependency, code-pattern and secret risks. It is published on npm as [`nuclear-option`](https://www.npmjs.com/package/nuclear-option) version 1.5.1, matching this repository.

![Demo](https://raw.githubusercontent.com/incrediblecrab/mlot-developer-media/main/gifs/nuclear-option.gif)

**Objective:** identify files and dependencies that could become single points of failure, then produce text or JSON output that can fail a build when a score crosses a threshold.

**Inputs:** Node.js, a project directory, JavaScript, TypeScript, JSON, YAML or `.env` files, and optional exclude and analyzer-focus settings.

**Files:**

- [`src/`](src/): TypeScript CLI, scanner, analyzers, formatters and exported library entry point
- [`.nuclear-option.example.yml`](.nuclear-option.example.yml): example rules, exclusions, scoring and reporting configuration
- [`CHANGELOG.md`](CHANGELOG.md): release notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md): development and contribution notes
- [`NUCLEAR_OPTION_IMPLEMENTATION.md`](NUCLEAR_OPTION_IMPLEMENTATION.md): implementation plan and architecture notes
- [`package.json`](package.json): npm metadata, scripts and the `nuclear-option` bin mapping
- [`tsconfig.json`](tsconfig.json): TypeScript build configuration

**Try it:** `npm install -g nuclear-option`, then `nuclear-option scan . --format text`, or run the checked-out copy with `node dist/cli.js --help` after `npm run build`.

## CLI reference

`nuclear-option scan [path] [options]` scans the supplied directory, using `.` when no path is supplied.

Options verified against `src/cli.ts`:

- `-o, --output <file>` writes results to a file instead of stdout.
- `-f, --format <format>` accepts `json` or `text`; the default is `text`.
- `--fail-threshold <score>` exits with code `1` when the maximum vulnerability score is greater than the threshold; the default is `100`.
- `--exclude <patterns...>` adds ignored glob patterns.
- `--focus <analyzers...>` limits scanning to `dependency`, `code-pattern` or `secrets` analyzers.
- `-v, --verbose` prints scan details and threshold failures.

## Output example

```text
Nuclear Option Security Analysis

SCAN SUMMARY
Path: /path/to/project
Files scanned: 42
Time elapsed: 120ms
Total vulnerabilities: 1

HIGH SEVERITY VULNERABILITIES

1. Possible hardcoded secret (Score: 90/100)
   src/config.ts:12
   The scanner found a secret-like pattern.
   Blast Radius: 1 components
   Remediation: Move the value to secure secret management.
```

## What it scans

The scanner searches `**/*.{js,ts,jsx,tsx,json,yml,yaml,env}` and skips `node_modules`, `dist`, `build`, `.git` and user-supplied exclusions. It runs the dependency analyzer, code-pattern analyzer and secrets analyzer unless `--focus` limits the set, then scores findings and sorts them from highest to lowest score.

## Library use

```typescript
import { Scanner } from 'nuclear-option';

const scanner = new Scanner();
const result = await scanner.scan({
  path: process.cwd(),
  format: 'json',
  failThreshold: 100
});

console.log(result.summary.total);
```

## Development

```bash
npm install
npm run build
npm test
npm run lint
```

`npm run build` compiles TypeScript to `dist/`. `npm test` runs Jest through `ts-jest`, and `npm run lint` checks `src/**/*.ts` with ESLint.

## Links

- [npm package](https://www.npmjs.com/package/nuclear-option)
- [Demo video](https://youtu.be/7CACK-tGWIw)
- [MLoT product page](https://mlot.ai/nuclear-option/)
- [Privacy policy](https://mlot.ai/privacy)
- [Issues](https://github.com/incrediblecrab/nuclear-option/issues)
- Publisher: [Max's Lab of Things](https://mlot.ai/)

## License

MIT. See [`LICENSE`](LICENSE).
