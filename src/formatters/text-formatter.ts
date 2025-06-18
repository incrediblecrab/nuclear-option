import chalk from 'chalk';
import { ScanResult, Vulnerability, Severity } from '../types';

export class TextFormatter {
  format(result: ScanResult): string {
    const output: string[] = [];
    
    // Header
    output.push(chalk.blue('🔍 Nuclear Option Security Analysis'));
    output.push(chalk.gray('━'.repeat(50)));
    output.push('');
    
    // Summary
    output.push(chalk.bold('SCAN SUMMARY'));
    output.push(chalk.gray('━'.repeat(20)));
    output.push(`📁 Path: ${result.metadata.path}`);
    output.push(`📄 Files scanned: ${result.summary.filesScanned}`);
    output.push(`⏱️  Time elapsed: ${result.summary.timeElapsed}ms`);
    output.push(`🔍 Total vulnerabilities: ${result.summary.total}`);
    output.push('');
    
    // Summary by severity
    if (result.summary.critical > 0) {
      output.push(chalk.red(`🚨 Critical: ${result.summary.critical}`));
    }
    if (result.summary.high > 0) {
      output.push(chalk.red(`⚠️  High: ${result.summary.high}`));
    }
    if (result.summary.medium > 0) {
      output.push(chalk.yellow(`📋 Medium: ${result.summary.medium}`));
    }
    if (result.summary.low > 0) {
      output.push(chalk.gray(`ℹ️  Low: ${result.summary.low}`));
    }
    output.push('');
    
    // Critical vulnerabilities
    const criticalVulns = result.vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
    if (criticalVulns.length > 0) {
      output.push(chalk.red.bold('CRITICAL VULNERABILITIES'));
      output.push(chalk.red('━'.repeat(30)));
      output.push('');
      
      criticalVulns.forEach((vuln, index) => {
        output.push(this.formatVulnerability(vuln, index + 1));
        output.push('');
      });
    }
    
    // High severity vulnerabilities
    const highVulns = result.vulnerabilities.filter(v => v.severity === Severity.HIGH);
    if (highVulns.length > 0) {
      output.push(chalk.red.bold('HIGH SEVERITY VULNERABILITIES'));
      output.push(chalk.red('━'.repeat(35)));
      output.push('');
      
      highVulns.slice(0, 10).forEach((vuln, index) => {
        output.push(this.formatVulnerability(vuln, index + 1));
        output.push('');
      });
      
      if (highVulns.length > 10) {
        output.push(chalk.gray(`... and ${highVulns.length - 10} more high severity issues`));
        output.push('');
      }
    }
    
    // Medium and low (summary only)
    const mediumVulns = result.vulnerabilities.filter(v => v.severity === Severity.MEDIUM);
    const lowVulns = result.vulnerabilities.filter(v => v.severity === Severity.LOW);
    
    if (mediumVulns.length > 0 || lowVulns.length > 0) {
      output.push(chalk.bold('OTHER ISSUES'));
      output.push(chalk.gray('━'.repeat(15)));
      
      if (mediumVulns.length > 0) {
        output.push(chalk.yellow(`📋 ${mediumVulns.length} medium severity issues`));
        mediumVulns.slice(0, 3).forEach(vuln => {
          output.push(chalk.gray(`   • ${vuln.message}`));
        });
        if (mediumVulns.length > 3) {
          output.push(chalk.gray(`   ... and ${mediumVulns.length - 3} more`));
        }
      }
      
      if (lowVulns.length > 0) {
        output.push(chalk.gray(`ℹ️  ${lowVulns.length} low severity issues`));
      }
      output.push('');
    }
    
    // Recommendations
    if (result.vulnerabilities.length > 0) {
      output.push(chalk.bold('RECOMMENDATIONS'));
      output.push(chalk.gray('━'.repeat(20)));
      
      const recommendations = this.generateRecommendations(result.vulnerabilities);
      recommendations.forEach(rec => {
        output.push(`• ${rec}`);
      });
    } else {
      output.push(chalk.green('✅ No critical vulnerabilities detected!'));
      output.push(chalk.gray('Your codebase appears to be secure from common architectural risks.'));
    }
    
    return output.join('\n');
  }
  
  private formatVulnerability(vuln: Vulnerability, index: number): string {
    const output: string[] = [];
    
    const severityColor = this.getSeverityColor(vuln.severity);
    
    output.push(severityColor(`${index}. ${vuln.message} (Score: ${vuln.score}/100)`));
    output.push(`   📍 ${vuln.file}${vuln.line ? `:${vuln.line}` : ''}`);
    output.push(`   ⚠️  ${vuln.details}`);
    
    if (vuln.blastRadius > 0) {
      output.push(`   💥 Blast Radius: ${vuln.blastRadius} components`);
    }
    
    output.push(`   🔧 Remediation: ${vuln.remediation}`);
    
    return output.join('\n');
  }
  
  private getSeverityColor(severity: Severity): typeof chalk.red {
    switch (severity) {
      case Severity.CRITICAL: return chalk.red.bold;
      case Severity.HIGH: return chalk.red;
      case Severity.MEDIUM: return chalk.yellow;
      case Severity.LOW: return chalk.gray;
      default: return chalk.white;
    }
  }
  
  private generateRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: string[] = [];
    
    const secretCount = vulnerabilities.filter(v => v.type === 'hardcoded-secret').length;
    const godObjectCount = vulnerabilities.filter(v => v.type === 'god-object').length;
    const depCount = vulnerabilities.filter(v => v.type === 'dependency').length;
    
    if (secretCount > 0) {
      recommendations.push('Implement secure secret management (environment variables, HashiCorp Vault)');
    }
    
    if (godObjectCount > 0) {
      recommendations.push('Refactor large files into smaller, focused modules');
    }
    
    if (depCount > 0) {
      recommendations.push('Review and pin dependency versions to prevent supply chain attacks');
    }
    
    if (vulnerabilities.some(v => v.score > 90)) {
      recommendations.push('Address critical vulnerabilities immediately - they pose systemic risks');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('Continue monitoring for new vulnerabilities as your codebase evolves');
    }
    
    return recommendations;
  }
}