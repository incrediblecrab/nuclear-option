import * as fs from 'fs/promises';
import * as path from 'path';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import { Analyzer, Vulnerability, VulnerabilityType, Severity, ScanOptions } from '../types';

export class DependencyAnalyzer implements Analyzer {
  name = 'dependency';
  private importGraph: Map<string, Set<string>> = new Map();
  
  async analyze(options: ScanOptions & { files?: string[] }): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Find package.json
    const packageJsonPath = path.join(options.path, 'package.json');
    
    try {
      const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));
      
      // Build import graph
      await this.buildImportGraph(options.files || []);
      
      // Check for unpinned dependencies
      const unpinnedVulns = await this.checkUnpinnedDependencies(packageJson, packageJsonPath);
      vulnerabilities.push(...unpinnedVulns);
      
      // Check for critical packages with many dependents
      const criticalVulns = await this.checkCriticalPackages(packageJson, packageJsonPath);
      vulnerabilities.push(...criticalVulns);
      
      // Check for packages with no recent updates
      const abandonedVulns = await this.checkAbandonedPackages(packageJson, packageJsonPath);
      vulnerabilities.push(...abandonedVulns);
      
    } catch (error) {
      // Package.json not found or invalid
    }
    
    return vulnerabilities;
  }
  
  private async buildImportGraph(files: string[]) {
    for (const file of files) {
      if (!file.match(/\.(js|ts|jsx|tsx)$/)) continue;
      
      try {
        const content = await fs.readFile(file, 'utf-8');
        const ast = parse(content, {
          sourceType: 'module',
          plugins: ['typescript', 'jsx'],
        });
        
        const imports = new Set<string>();
        
        traverse(ast, {
          ImportDeclaration(path) {
            imports.add(path.node.source.value);
          },
          CallExpression(path) {
            if (path.node.callee.type === 'Identifier' && 
                path.node.callee.name === 'require' &&
                path.node.arguments[0]?.type === 'StringLiteral') {
              imports.add(path.node.arguments[0].value);
            }
          },
        });
        
        this.importGraph.set(file, imports);
      } catch (error) {
        // Skip files that can't be parsed
      }
    }
  }
  
  private async checkUnpinnedDependencies(packageJson: any, packageJsonPath: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const [pkg, version] of Object.entries(deps)) {
      if (typeof version === 'string' && (version.includes('^') || version.includes('~') || version === '*')) {
        const dependents = this.findPackageDependents(pkg);
        
        vulnerabilities.push({
          id: `dep-unpinned-${pkg}`,
          type: VulnerabilityType.DEPENDENCY,
          severity: version === '*' ? Severity.HIGH : Severity.MEDIUM,
          score: 0, // Will be calculated by scoring engine
          file: packageJsonPath,
          message: `Unpinned dependency: ${pkg}@${version}`,
          details: `Package '${pkg}' uses version range '${version}' which could allow malicious updates`,
          blastRadius: dependents.length,
          affectedComponents: dependents,
          remediation: `Pin ${pkg} to a specific version (e.g., "${version.replace(/[^0-9.]/g, '')}")`
        });
      }
    }
    
    return vulnerabilities;
  }
  
  private async checkCriticalPackages(packageJson: any, packageJsonPath: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const criticalPackages = [
      'express', 'fastify', 'koa', 'hapi', // Web frameworks
      'jsonwebtoken', 'passport', 'bcrypt', 'argon2', // Auth
      'mongoose', 'sequelize', 'typeorm', 'prisma', // ORMs
      'axios', 'node-fetch', 'request', // HTTP clients
      'dotenv', 'config', // Config management
    ];
    
    const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const pkg of criticalPackages) {
      if (deps[pkg]) {
        const dependents = this.findPackageDependents(pkg);
        
        if (dependents.length > 20) {
          vulnerabilities.push({
            id: `dep-critical-${pkg}`,
            type: VulnerabilityType.SINGLE_POINT_OF_FAILURE,
            severity: Severity.HIGH,
            score: 0,
            file: packageJsonPath,
            message: `Critical dependency with high usage: ${pkg}`,
            details: `Package '${pkg}' is used by ${dependents.length} components. Compromise would have widespread impact.`,
            blastRadius: dependents.length,
            affectedComponents: dependents.slice(0, 10), // Limit for readability
            remediation: `Consider implementing abstraction layer around ${pkg} to reduce direct dependencies`
          });
        }
      }
    }
    
    return vulnerabilities;
  }
  
  private async checkAbandonedPackages(packageJson: any, packageJsonPath: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // In a real implementation, we'd check npm registry for last publish date
    // For now, we'll flag known problematic packages
    const abandonedPackages = ['request', 'node-uuid', 'jade'];
    const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    for (const pkg of abandonedPackages) {
      if (deps[pkg]) {
        vulnerabilities.push({
          id: `dep-abandoned-${pkg}`,
          type: VulnerabilityType.DEPENDENCY,
          severity: Severity.MEDIUM,
          score: 0,
          file: packageJsonPath,
          message: `Potentially abandoned package: ${pkg}`,
          details: `Package '${pkg}' appears to be unmaintained and may have unpatched vulnerabilities`,
          blastRadius: this.findPackageDependents(pkg).length,
          affectedComponents: this.findPackageDependents(pkg),
          remediation: `Replace ${pkg} with actively maintained alternative`
        });
      }
    }
    
    return vulnerabilities;
  }
  
  private findPackageDependents(packageName: string): string[] {
    const dependents: string[] = [];
    
    for (const [file, imports] of this.importGraph.entries()) {
      if (imports.has(packageName)) {
        dependents.push(path.relative(process.cwd(), file));
      }
    }
    
    return dependents;
  }
}