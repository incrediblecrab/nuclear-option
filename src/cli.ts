#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Scanner } from './core/scanner';
import { TextFormatter } from './formatters/text-formatter';
import { JsonFormatter } from './formatters/json-formatter';
import { version } from '../package.json';

const program = new Command();

program
  .name('nuclear-option')
  .description('Find critical vulnerabilities and single points of failure in your codebase')
  .version(version)
  .addHelpText('after', '\nFor more information, visit: https://github.com/incrediblecrab/nuclear-option');

program
  .command('scan [path]')
  .description('Scan a directory for vulnerabilities')
  .option('-o, --output <file>', 'Output results to file')
  .option('-f, --format <format>', 'Output format (json|text)', 'text')
  .option('--fail-threshold <score>', 'Fail if any vulnerability exceeds this score', '100')
  .option('--exclude <patterns...>', 'Exclude file patterns')
  .option('--focus <analyzers...>', 'Focus on specific analyzers (dependency, code-pattern, secrets)')
  .option('-v, --verbose', 'Verbose output')
  .action(async (scanPath = '.', options) => {
    try {
      const scanner = new Scanner();
      
      if (options.verbose) {
        console.log(chalk.blue('🔍 Nuclear Option Security Analysis'));
        console.log(chalk.gray('━'.repeat(50)));
        console.log(chalk.gray(`Scanning: ${path.resolve(scanPath)}`));
        console.log('');
      }
      
      const result = await scanner.scan({
        path: path.resolve(scanPath),
        format: options.format,
        output: options.output,
        failThreshold: parseInt(options.failThreshold),
        exclude: options.exclude,
        focus: options.focus,
        verbose: options.verbose,
      });
      
      // Format output
      let formattedOutput: string;
      if (options.format === 'json') {
        const formatter = new JsonFormatter();
        formattedOutput = formatter.format(result);
      } else {
        const formatter = new TextFormatter();
        formattedOutput = formatter.format(result);
      }
      
      // Output to file or console
      if (options.output) {
        await fs.writeFile(options.output, formattedOutput);
        if (options.verbose) {
          console.log(chalk.green(`Results written to ${options.output}`));
        }
      } else {
        console.log(formattedOutput);
      }
      
      // Check fail threshold
      const threshold = parseInt(options.failThreshold);
      const maxScore = Math.max(...result.vulnerabilities.map(v => v.score), 0);
      
      if (maxScore > threshold) {
        if (options.verbose) {
          console.log('');
          console.log(chalk.red(`❌ Build failed: vulnerability score ${maxScore} exceeds threshold ${threshold}`));
        }
        process.exit(1);
      }
      
    } catch (error) {
      console.error(chalk.red('Error during scan:'), error instanceof Error ? error.message : String(error));
      if (options.verbose && error instanceof Error) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// Error handling
process.on('unhandledRejection', (error) => {
  console.error(chalk.red('Unhandled error:'), error);
  process.exit(1);
});

program.parse();