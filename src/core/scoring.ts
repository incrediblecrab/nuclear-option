import { Vulnerability, Severity } from '../types';

const SEVERITY_WEIGHTS = {
  critical: 90,
  high: 70,
  medium: 40,
  low: 20,
};

const TYPE_MULTIPLIERS = {
  'hardcoded-secret': 1.5,
  'single-point-of-failure': 1.4,
  'god-object': 1.2,
  'dependency': 1.1,
  'circular-dependency': 1.0,
};

export function calculateScore(vulnerability: Vulnerability): number {
  let score = SEVERITY_WEIGHTS[vulnerability.severity];
  
  // Apply type multiplier
  score *= TYPE_MULTIPLIERS[vulnerability.type] || 1.0;
  
  // Factor in blast radius (logarithmic scale)
  if (vulnerability.blastRadius > 0) {
    score += Math.min(Math.log10(vulnerability.blastRadius) * 5, 10);
  }
  
  // Factor in affected components
  if (vulnerability.affectedComponents.length > 10) {
    score += Math.min(vulnerability.affectedComponents.length / 10, 5);
  }
  
  // Cap at 100
  return Math.min(Math.round(score), 100);
}