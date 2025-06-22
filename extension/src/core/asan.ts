import { exec, ChildProcess  } from 'child_process';
import * as path from 'path';
import { existsSync } from 'fs';
import * as vscode from 'vscode';

export async function compileWithASan(cppFilePath: string, outputPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const command = `clang++ -fsanitize=address -fno-omit-frame-pointer -Wno-return-stack-address -g "${cppFilePath}" -o "${outputPath}"`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) reject(`Compilation failed: ${error.message}`);
      if (stderr) reject(`Compiler warnings: ${stderr}`);
      resolve();
    });
  });
}

export async function runWithASan(
  executablePath: string,
  testInput: string,  // Can be a literal test string or a path to an input file
  asanOptions: string,
  token?: vscode.CancellationToken
): Promise<string> {
  // Determine if `testInput` refers to an existing file on disk
  const isFileInput = testInput.includes(path.sep) && existsSync(testInput);

  // If it's a file, ASan can read it via the @<filename> syntax;
  // otherwise pass it as a normal argument string.
  const inputArg = isFileInput ? `@"${testInput}"` : `"${testInput}"`;

  // Build the full command line
  const command = `ASAN_OPTIONS=${asanOptions} "${executablePath}" ${inputArg}`;

  return new Promise<string>((resolve, reject) => {
    // Launch the process
    const child: ChildProcess = exec(command, (error, stdout, stderr) => {
      if (error && token?.isCancellationRequested) {
        return reject(new Error('Operation cancelled'));
      }
      // ASan diagnostics always go to stderr
      resolve(stderr);
    });

    // If provided, wire up the cancellation token
    if (token) {
      token.onCancellationRequested(() => {
        child.kill();
        reject(new Error('Operation cancelled'));
      });
    }
  });
}