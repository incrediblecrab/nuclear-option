import { glob } from 'glob';
import * as path from 'path';
import * as fs from 'fs/promises';
import { ScanOptions, ScanResult, Vulnerability, Analyzer } from '../types';
import { DependencyAnalyzer } from '../analyzers/dependency-analyzer';
import { CodePatternAnalyzer } from '../analyzers/code-pattern-analyzer';
import { SecretsAnalyzer } from '../analyzers/secrets-analyzer';
import { calculateScore } from './scoring';

export class Scanner {
  private analyzers: Analyzer[] = [];

  constructor() {
    this.analyzers = [
      new DependencyAnalyzer(),
      new CodePatternAnalyzer(),
      new SecretsAnalyzer(),
    ];
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const vulnerabilities: Vulnerability[] = [];
    
    // Get all files to scan
    const files = await this.getFilesToScan(options);
    
    // Run all analyzers
    for (const analyzer of this.analyzers) {
      if (options.focus && !options.focus.includes(analyzer.name)) {
        continue;
      }
      
      try {
        const results = await analyzer.analyze({ ...options, files });
        vulnerabilities.push(...results);
      } catch (error) {
        if (options.verbose) {
          console.error(`Error in ${analyzer.name}:`, error);
        }
      }
    }
    
    // Calculate scores and sort by severity
    const scoredVulnerabilities = vulnerabilities.map(vuln => ({
      ...vuln,
      score: calculateScore(vuln),
    })).sort((a, b) => b.score - a.score);
    
    return {
      vulnerabilities: scoredVulnerabilities,
      summary: {
        total: scoredVulnerabilities.length,
        critical: scoredVulnerabilities.filter(v => v.severity === 'critical').length,
        high: scoredVulnerabilities.filter(v => v.severity === 'high').length,
        medium: scoredVulnerabilities.filter(v => v.severity === 'medium').length,
        low: scoredVulnerabilities.filter(v => v.severity === 'low').length,
        timeElapsed: Date.now() - startTime,
        filesScanned: files.length,
      },
      metadata: {
        scanDate: new Date().toISOString(),
        version: '0.1.0',
        path: options.path,
      },
    };
  }
  
  private async getFilesToScan(options: ScanOptions): Promise<string[]> {
    const excludePatterns = [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      ...(options.exclude || []),
    ];
    
    const files = await glob('**/*.{js,ts,jsx,tsx,json,yml,yaml,env}', {
      cwd: options.path,
      absolute: true,
      ignore: excludePatterns,
    });
    
    return files;
  }
}