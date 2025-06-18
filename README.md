# Nuclear Option 🔍💥

> Find the Jenga blocks in your codebase - identify critical vulnerabilities and single points of failure before they bring down your entire system.

## What is Nuclear Option?

Nuclear Option is a security analysis tool that goes beyond traditional vulnerability scanning. Instead of just finding bugs, it identifies architectural weaknesses - the critical components that, if compromised, could cause cascading failures throughout your application.

## Key Features

- **Dependency Analysis**: Find over-relied upon packages and supply chain risks
- **Architecture Scanning**: Identify God objects, single points of failure, and bottlenecks  
- **Impact Assessment**: Understand the "blast radius" of each vulnerability
- **Actionable Remediation**: Get specific guidance on how to fix issues
- **CI/CD Integration**: Fail builds when critical vulnerabilities are detected

## Quick Start

```bash
# Install globally
npm install -g nuclear-option

# Scan your project
nuclear-option scan ./src

# Generate detailed report
nuclear-option scan --output=report.html

# CI/CD mode
nuclear-option scan --format=json --fail-threshold=80
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

## License

MIT