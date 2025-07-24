# Contributing to Nuclear Option

Thank you for your interest in contributing to Nuclear Option! 🎉

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/nuclear-option.git
   cd nuclear-option
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Run tests** to ensure everything works:
   ```bash
   npm test
   ```

## Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Make your changes** and add tests
3. **Run the test suite**:
   ```bash
   npm test
   npm run lint
   npm run build
   ```
4. **Test manually**:
   ```bash
   npm start -- scan /path/to/test/project
   ```
5. **Commit your changes**:
   ```bash
   git commit -m "Add your descriptive commit message"
   ```
6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request** on GitHub

## What We're Looking For

### New Analyzers
- **Pattern-based analyzers** for specific vulnerability types
- **Framework-specific modules** (React, Vue, Express, etc.)
- **Language support** beyond JavaScript/TypeScript

### Improvements
- **Performance optimizations** for large codebases
- **Better accuracy** in vulnerability detection
- **Enhanced reporting** formats and visualizations
- **CI/CD integrations** (GitHub Actions, Jenkins, etc.)

### Bug Fixes
- **False positive reduction**
- **Edge case handling**
- **Cross-platform compatibility**

## Code Style

- Follow existing TypeScript patterns
- Add tests for new features
- Update documentation for new analyzers
- Use meaningful commit messages

## Creating New Analyzers

All analyzers implement the `Analyzer` interface:

```typescript
export interface Analyzer {
  name: string;
  analyze(options: ScanOptions): Promise<Vulnerability[]>;
}
```

See `src/analyzers/secrets-analyzer.ts` for a complete example.

## Testing

- Add unit tests in `src/__tests__/`
- Test with real-world codebases
- Include both positive and negative test cases

## Questions?

- 💬 [Open an issue](https://github.com/incrediblecrab/nuclear-option/issues) for questions
- 🐛 [Report bugs](https://github.com/incrediblecrab/nuclear-option/issues) with reproduction steps
- 💡 [Suggest features](https://github.com/incrediblecrab/nuclear-option/issues) with use cases

## License

By contributing, you agree that your contributions will be licensed under the MIT License.