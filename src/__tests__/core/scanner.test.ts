import { Scanner } from '../../core/scanner';
import * as fs from 'fs/promises';
import { glob } from 'glob';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('glob');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockGlob = glob as jest.MockedFunction<typeof glob>;

describe('Scanner', () => {
  let scanner: Scanner;
  
  beforeEach(() => {
    scanner = new Scanner();
    jest.clearAllMocks();
  });
  
  describe('scan', () => {
    it('should return scan results with correct structure', async () => {
      // Mock glob to return empty file list
      mockGlob.mockResolvedValue([]);
      
      const result = await scanner.scan({
        path: '/test/path'
      });
      
      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('metadata');
      expect(result.vulnerabilities).toBeInstanceOf(Array);
    });
    
    it('should respect exclude patterns', async () => {
      mockGlob.mockResolvedValue([]);
      
      await scanner.scan({
        path: '/test/path',
        exclude: ['**/test/**']
      });
      
      expect(mockGlob).toHaveBeenCalledWith(
        '**/*.{js,ts,jsx,tsx,json,yml,yaml,env}',
        expect.objectContaining({
          ignore: expect.arrayContaining(['**/test/**'])
        })
      );
    });
  });
});