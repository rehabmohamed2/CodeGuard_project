import { compileWithASan, runWithASan } from './asan';
import { Checker } from './types';
import { unlink } from 'fs/promises';
import * as path from 'path';

export class AnalysisCore {
  constructor(private checkers: Checker[]) {}

  // File-based analysis flow
  async analyzeFile(
    cppPath: string,
    options: {
      cancellationToken?: { isCancellationRequested: boolean };
      onProgress?: (message: string) => void;
    }
  ) {
    // Generate the output file path in the current working directory.
    // (For example, "example.cpp" becomes "example")
    const outputPath = cppPath.replace(/\.cpp$/, '');

    try {
      // options.onProgress?.('Compiling with ASan...');
      await compileWithASan(cppPath, outputPath);

      const sarifData = [];
      for (const checker of this.checkers) {
        if (options.cancellationToken?.isCancellationRequested) {
          throw new Error('Analysis cancelled');
        }

        // options.onProgress?.(`Running ${checker.name} check...`);
        const asanOutput = await runWithASan(
          outputPath,
          checker.testInput,
          checker.asanOptions
        );
        const vuln = checker.parse(asanOutput);
        if (vuln) {
          sarifData.push(checker.generateSarif(vuln));
        }
      }

      if (sarifData.length > 0) {
        const sarifLog = [{
          $schema: "http://json.schemastore.org/sarif-2.1.0",
          version: "2.1.0",
          runs: [{
            tool: {
              driver: {
                name: "Secure Code Analyzer",
                rules: sarifData.map(d => d.rule),
                informationUri: "https://github.com/your-repo"
              }
            },
            results: sarifData.flatMap(d => d.result),
          }]
        }];
        return sarifLog;
      } else {
        return sarifData;
      }
    } finally {
      // Regardless of analysis outcome, delete the compiled file.
      try {
        await unlink(outputPath);
      } catch (err) {
        // Log an error if deletion fails.
        console.error(`Failed to delete compiled file ${outputPath}:`, err);
      }
    }
  }

  // Fuzzing-based analysis flow
  async analyzeCrashes(
    executablePath: string,
    crashInputs: string[],
    options: {
      cancellationToken?: { isCancellationRequested: boolean };
      onProgress?: (message: string) => void;
    }
  ) {
    const sarifData = [];
  
    try {
      for (const inputFile of crashInputs) {
        if (options.cancellationToken?.isCancellationRequested) {
          throw new Error('Analysis cancelled');
        }
  
        options.onProgress?.(`Testing crash input: ${path.basename(inputFile)}`);
  
        for (const checker of this.checkers) {
          // Run the crash input through ASan
          const asanOutput = await runWithASan(
            executablePath,
            inputFile,           // pass the file path
            checker.asanOptions
          );
  
          const vuln = checker.parse(asanOutput);
          if (vuln) {
            sarifData.push(checker.generateSarif(vuln));
          }
        }
      }
  
      // Build and return the SARIF log if we found any vulnerabilities
      if (sarifData.length > 0) {
        const sarifLog = [{
          $schema: "http://json.schemastore.org/sarif-2.1.0",
          version: "2.1.0",
          runs: [{
            tool: {
              driver: {
                name: "Secure Code Analyzer",
                rules: sarifData.map(d => d.rule),
                informationUri: "https://github.com/your-repo"
              }
            },
            results: sarifData.flatMap(d => d.result),
          }]
        }];
        return sarifLog;
      }
      else{
        // No vulnerabilities → return empty array
        return sarifData;
      }
    } finally {
    }
  }
}
