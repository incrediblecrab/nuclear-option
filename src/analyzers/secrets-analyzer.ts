import * as fs from 'fs/promises';
import * as path from 'path';
import { Analyzer, Vulnerability, VulnerabilityType, Severity, ScanOptions } from '../types';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}

export class SecretsAnalyzer implements Analyzer {
  name = 'secrets';
  
  private secretPatterns: SecretPattern[] = [
    {
      name: 'AWS Access Key',
      pattern: /AKIA[0-9A-Z]{16}/g,
      severity: Severity.CRITICAL,
      description: 'AWS Access Key detected'
    },
    {
      name: 'AWS Secret Key',
      pattern: /aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi,
      severity: Severity.CRITICAL,
      description: 'AWS Secret Access Key detected'
    },
    {
      name: 'Generic API Key',
      pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_-]{16,}['"]/gi,
      severity: Severity.HIGH,
      description: 'Generic API key detected'
    },
    {
      name: 'JWT Token',
      pattern: /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
      severity: Severity.HIGH,
      description: 'JWT token detected'
    },
    {
      name: 'Database Password',
      pattern: /(password|pwd|pass)\s*[:=]\s*['"][^'"\s]{6,}['"]/gi,
      severity: Severity.HIGH,
      description: 'Potential database password detected'
    },
    {
      name: 'Private Key',
      pattern: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g,
      severity: Severity.CRITICAL,
      description: 'Private key detected'
    },
    {
      name: 'GitHub Token',
      pattern: /gh[ps]_[a-zA-Z0-9_]{36,}/g,
      severity: Severity.HIGH,
      description: 'GitHub personal access token detected'
    },
    {
      name: 'Slack Token',
      pattern: /xox[baprs]-[a-zA-Z0-9-]+/g,
      severity: Severity.HIGH,
      description: 'Slack token detected'
    },
    {
      name: 'Generic Secret',
      pattern: /(secret|token|key)\s*[:=]\s*['"][a-zA-Z0-9_+/=-]{20,}['"]/gi,
      severity: Severity.MEDIUM,
      description: 'Generic secret pattern detected'
    }
  ];
  
  async analyze(options: ScanOptions & { files?: string[] }): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const files = options.files || [];
    
    for (const file of files) {
      // Skip binary files and specific extensions
      if (file.match(/\.(jpg|jpeg|png|gif|ico|pdf|zip|tar|gz|exe|bin)$/i)) continue;
      
      try {
        const content = await fs.readFile(file, 'utf-8');
        const fileVulns = this.scanFileContent(file, content);
        vulnerabilities.push(...fileVulns);
      } catch (error) {
        // Skip files that can't be read as text
      }
    }
    
    return vulnerabilities;
  }
  
  private scanFileContent(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');
    
    for (const pattern of this.secretPatterns) {
      let match;
      
      // Reset regex to scan from beginning
      pattern.pattern.lastIndex = 0;
      
      while ((match = pattern.pattern.exec(content)) !== null) {
        // Find line number
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const lineContent = lines[lineNumber - 1] || '';
        
        // Skip false positives (comments, examples, etc.)
        if (this.isFalsePositive(lineContent, match[0])) {
          continue;
        }
        
        vulnerabilities.push({
          id: `secret-${pattern.name.toLowerCase().replace(/\s+/g, '-')}-${lineNumber}`,
          type: VulnerabilityType.HARDCODED_SECRET,
          severity: pattern.severity,
          score: 0,
          file,
          line: lineNumber,
          message: `${pattern.description} in ${path.basename(file)}`,
          details: `Found potential ${pattern.name.toLowerCase()} on line ${lineNumber}. Hardcoded secrets pose significant security risks.`,
          blastRadius: this.calculateSecretBlastRadius(pattern.severity),
          affectedComponents: [path.relative(process.cwd(), file)],
          remediation: `Move secret to environment variables or secure secret management system. Use process.env.${this.suggestEnvVarName(pattern.name)}`
        });
        
        // Prevent infinite loops
        if (pattern.pattern.global && pattern.pattern.lastIndex === match.index) {
          pattern.pattern.lastIndex++;
        }
      }
    }
    
    return vulnerabilities;
  }
  
  private isFalsePositive(lineContent: string, match: string): boolean {
    const line = lineContent.toLowerCase();
    
    // Skip comments
    if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) {
      return true;
    }
    
    // Skip example/placeholder values
    const examples = ['example', 'placeholder', 'your-key-here', 'xxx', 'test', 'demo', 'sample'];
    if (examples.some(ex => match.toLowerCase().includes(ex))) {
      return true;
    }
    
    // Skip very short matches that are likely false positives
    if (match.length < 8) {
      return true;
    }
    
    return false;
  }
  
  private calculateSecretBlastRadius(severity: Severity): number {
    switch (severity) {
      case Severity.CRITICAL: return 100; // System-wide access
      case Severity.HIGH: return 50; // Service-level access
      case Severity.MEDIUM: return 10; // Component-level access
      default: return 1;
    }
  }
  
  private suggestEnvVarName(secretType: string): string {
    return secretType.toUpperCase().replace(/\s+/g, '_');
  }
}