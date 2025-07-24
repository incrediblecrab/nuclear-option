import { calculateScore } from '../../core/scoring';
import { Vulnerability, VulnerabilityType, Severity } from '../../types';

describe('calculateScore', () => {
  const baseVulnerability: Vulnerability = {
    id: 'test-vuln',
    type: VulnerabilityType.DEPENDENCY,
    severity: Severity.MEDIUM,
    score: 0,
    file: '/test/file.js',
    message: 'Test vulnerability',
    details: 'Test details',
    blastRadius: 0,
    affectedComponents: [],
    remediation: 'Test remediation'
  };
  
  it('should calculate base score based on severity', () => {
    const criticalVuln = { ...baseVulnerability, severity: Severity.CRITICAL };
    const highVuln = { ...baseVulnerability, severity: Severity.HIGH };
    const mediumVuln = { ...baseVulnerability, severity: Severity.MEDIUM };
    const lowVuln = { ...baseVulnerability, severity: Severity.LOW };
    
    expect(calculateScore(criticalVuln)).toBeGreaterThan(calculateScore(highVuln));
    expect(calculateScore(highVuln)).toBeGreaterThan(calculateScore(mediumVuln));
    expect(calculateScore(mediumVuln)).toBeGreaterThan(calculateScore(lowVuln));
  });
  
  it('should apply type multipliers', () => {
    const secretVuln = { ...baseVulnerability, type: VulnerabilityType.HARDCODED_SECRET };
    const depVuln = { ...baseVulnerability, type: VulnerabilityType.DEPENDENCY };
    
    expect(calculateScore(secretVuln)).toBeGreaterThan(calculateScore(depVuln));
  });
  
  it('should factor in blast radius', () => {
    const highBlastVuln = { ...baseVulnerability, blastRadius: 100 };
    const lowBlastVuln = { ...baseVulnerability, blastRadius: 1 };
    
    expect(calculateScore(highBlastVuln)).toBeGreaterThan(calculateScore(lowBlastVuln));
  });
  
  it('should cap score at 100', () => {
    const maxVuln = {
      ...baseVulnerability,
      severity: Severity.CRITICAL,
      type: VulnerabilityType.HARDCODED_SECRET,
      blastRadius: 1000,
      affectedComponents: new Array(100).fill('component')
    };
    
    expect(calculateScore(maxVuln)).toBeLessThanOrEqual(100);
  });
});