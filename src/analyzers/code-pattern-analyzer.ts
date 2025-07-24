import * as fs from 'fs/promises';
import * as path from 'path';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import { Analyzer, Vulnerability, VulnerabilityType, Severity, ScanOptions } from '../types';

interface FileMetrics {
  file: string;
  lineCount: number;
  functionCount: number;
  classMethodCount: number;
  importCount: number;
  exportCount: number;
  complexityScore: number;
}

export class CodePatternAnalyzer implements Analyzer {
  name = 'code-pattern';
  
  async analyze(options: ScanOptions & { files?: string[] }): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const files = options.files || [];
    
    for (const file of files) {
      if (!file.match(/\.(js|ts|jsx|tsx)$/)) continue;
      
      try {
        const metrics = await this.analyzeFile(file);
        
        // Check for God objects
        if (metrics.lineCount > 500 || metrics.functionCount > 20) {
          vulnerabilities.push(this.createGodObjectVulnerability(metrics));
        }
        
        // Check for files with too many responsibilities
        if (metrics.exportCount > 10 && metrics.functionCount > 15) {
          vulnerabilities.push(this.createHighResponsibilityVulnerability(metrics));
        }
        
      } catch (error) {
        // Skip files that can't be analyzed
      }
    }
    
    return vulnerabilities;
  }
  
  private async analyzeFile(file: string): Promise<FileMetrics> {
    const content = await fs.readFile(file, 'utf-8');
    const lines = content.split('\n');
    
    const metrics: FileMetrics = {
      file,
      lineCount: lines.length,
      functionCount: 0,
      classMethodCount: 0,
      importCount: 0,
      exportCount: 0,
      complexityScore: 0,
    };
    
    try {
      const ast = parse(content, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'decorators-legacy'],
      });
      
      traverse(ast, {
        FunctionDeclaration() {
          metrics.functionCount++;
        },
        FunctionExpression() {
          metrics.functionCount++;
        },
        ArrowFunctionExpression() {
          metrics.functionCount++;
        },
        ClassMethod() {
          metrics.classMethodCount++;
        },
        ImportDeclaration() {
          metrics.importCount++;
        },
        ExportNamedDeclaration() {
          metrics.exportCount++;
        },
        ExportDefaultDeclaration() {
          metrics.exportCount++;
        },
        IfStatement() {
          metrics.complexityScore += 1;
        },
        ForStatement() {
          metrics.complexityScore += 2;
        },
        WhileStatement() {
          metrics.complexityScore += 2;
        },
        SwitchStatement() {
          metrics.complexityScore += 2;
        },
        ConditionalExpression() {
          metrics.complexityScore += 1;
        },
      });
      
      // Calculate total complexity
      metrics.complexityScore += metrics.functionCount * 2;
      metrics.complexityScore += metrics.classMethodCount * 2;
      
    } catch (error) {
      // If parsing fails, use line-based heuristics
      metrics.functionCount = (content.match(/function\s+\w+|=>\s*{|:\s*\(/g) || []).length;
      metrics.importCount = (content.match(/^import\s+/gm) || []).length;
      metrics.exportCount = (content.match(/^export\s+/gm) || []).length;
    }
    
    return metrics;
  }
  
  private createGodObjectVulnerability(metrics: FileMetrics): Vulnerability {
    const relativePath = path.relative(process.cwd(), metrics.file);
    
    return {
      id: `god-object-${path.basename(metrics.file)}`,
      type: VulnerabilityType.GOD_OBJECT,
      severity: metrics.lineCount > 1000 ? Severity.HIGH : Severity.MEDIUM,
      score: 0,
      file: metrics.file,
      message: `God object detected: ${path.basename(metrics.file)}`,
      details: `File has ${metrics.lineCount} lines and ${metrics.functionCount} functions. This indicates too many responsibilities.`,
      blastRadius: metrics.importCount * 3, // Estimate based on imports
      affectedComponents: [`${relativePath} (and its dependents)`],
      remediation: 'Split this file into smaller, focused modules with single responsibilities',
    };
  }
  
  private createHighResponsibilityVulnerability(metrics: FileMetrics): Vulnerability {
    const relativePath = path.relative(process.cwd(), metrics.file);
    
    return {
      id: `high-responsibility-${path.basename(metrics.file)}`,
      type: VulnerabilityType.GOD_OBJECT,
      severity: Severity.MEDIUM,
      score: 0,
      file: metrics.file,
      message: `Module with too many exports: ${path.basename(metrics.file)}`,
      details: `File exports ${metrics.exportCount} items with ${metrics.functionCount} functions. Consider splitting responsibilities.`,
      blastRadius: metrics.exportCount * 2,
      affectedComponents: [`${relativePath} (${metrics.exportCount} exports)`],
      remediation: 'Group related functionality and split into focused modules',
    };
  }
}