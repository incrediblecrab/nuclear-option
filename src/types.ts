export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  score: number;
  file: string;
  line?: number;
  column?: number;
  message: string;
  details: string;
  blastRadius: number;
  affectedComponents: string[];
  remediation: string;
}

export enum VulnerabilityType {
  DEPENDENCY = 'dependency',
  GOD_OBJECT = 'god-object',
  HARDCODED_SECRET = 'hardcoded-secret',
  SINGLE_POINT_OF_FAILURE = 'single-point-of-failure',
  CIRCULAR_DEPENDENCY = 'circular-dependency',
}

export enum Severity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface ScanOptions {
  path: string;
  format?: 'text' | 'json' | 'html';
  output?: string;
  failThreshold?: number;
  exclude?: string[];
  focus?: string[];
  verbose?: boolean;
  files?: string[];
}

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    timeElapsed: number;
    filesScanned: number;
  };
  metadata: {
    scanDate: string;
    version: string;
    path: string;
  };
}

export interface Analyzer {
  name: string;
  analyze(options: ScanOptions): Promise<Vulnerability[]>;
}