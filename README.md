# Nuclear Option 🔍💥

> Find the Jenga blocks in your codebase - identify critical vulnerabilities and single points of failure before they bring down your entire system.

[![npm version](https://badge.fury.io/js/nuclear-option.svg)](https://badge.fury.io/js/nuclear-option)
[![GitHub](https://img.shields.io/github/license/incrediblecrab/nuclear-option)](https://github.com/incrediblecrab/nuclear-option/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/incrediblecrab/nuclear-option)](https://github.com/incrediblecrab/nuclear-option/issues)

## What is Nuclear Option?

Nuclear Option is a security analysis tool that goes beyond traditional vulnerability scanning. Instead of just finding bugs, it identifies architectural weaknesses - the critical components that, if compromised, could cause cascading failures throughout your application.

## Key Features

- **Dependency Analysis**: Find over-relied upon packages and supply chain risks
- **Architecture Scanning**: Identify God objects, single points of failure, and bottlenecks  
- **Impact Assessment**: Understand the "blast radius" of each vulnerability
- **Actionable Remediation**: Get specific guidance on how to fix issues
- **CI/CD Integration**: Fail builds when critical vulnerabilities are detected

## Installation

```bash
# Install globally from npm
npm install -g nuclear-option

# Or install from GitHub
npm install -g https://github.com/incrediblecrab/nuclear-option.git

# Or clone and build locally
git clone https://github.com/incrediblecrab/nuclear-option.git
cd nuclear-option
npm install && npm run build
npm link  # Make available globally
```

## Quick Start

```bash
# Scan your project
nuclear-option scan ./src

# Generate detailed report
nuclear-option scan --output=report.json

# CI/CD mode
nuclear-option scan --format=json --fail-threshold=80

# Focus on specific vulnerability types
nuclear-option scan --focus=secrets,dependency

# Exclude test files and other patterns
nuclear-option scan --exclude="**/test/**" "**/node_modules/**"
```

## Why Nuclear Option?

Recent security incidents have shown that attackers don't need to find many vulnerabilities - they just need to find the right one. The "Jenga block" that brings everything down. Nuclear Option helps you find these critical weaknesses before attackers do.

## Example Output

```
🔍 Found 3 CRITICAL vulnerabilities:

1. AuthService (Score: 95/100)
   Single point of authentication affecting 127 components
   
2. DatabaseConnection (Score: 92/100)  
   No failover mechanism affecting 89 components
   
3. ConfigManager (Score: 91/100)
   Hardcoded credentials with system-wide impact
```

## Documentation

See [NUCLEAR_OPTION_IMPLEMENTATION.md](./NUCLEAR_OPTION_IMPLEMENTATION.md) for detailed implementation plans and architecture.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](https://github.com/incrediblecrab/nuclear-option/blob/main/CONTRIBUTING.md) for details.

### Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/incrediblecrab/nuclear-option/issues) on GitHub.

### Development

```bash
# Clone the repository
git clone https://github.com/incrediblecrab/nuclear-option.git
cd nuclear-option

# Install dependencies
npm install

# Run tests
npm test

# Build the project
npm run build

# Test locally
npm start -- scan /path/to/your/project
```

## Author

Created by [mlot.ai](https://mlot.ai) - AI-powered development tools and security solutions.

## License

MIT License - see the [LICENSE](https://github.com/incrediblecrab/nuclear-option/blob/main/LICENSE) file for details.