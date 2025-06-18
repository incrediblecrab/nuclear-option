import { ScanResult } from '../types';

export class JsonFormatter {
  format(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }
}