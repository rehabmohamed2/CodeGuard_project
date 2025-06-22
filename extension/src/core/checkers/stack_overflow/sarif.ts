import * as path from 'path';
import { VulnerabilityLocation } from '../../types';
import { encodeSarifUri, createCodeFlow, createStackFrame, getCodeSnippet } from '../../sarif';

export function generateSarif(location: VulnerabilityLocation) {
  const encodedUri = encodeSarifUri(location.declarationFile);
  
  // Get code snippets
  const bufferSnippet = getCodeSnippet(location.bufferDeclarationLine, location.declarationFile);
  const vulnSnippet = getCodeSnippet(location.declarationLine, location.declarationFile);

  return {
    rule: {
      id: "CWE-121",
      name: "Stack-based Buffer Overflow",
      shortDescription: { text: "Detects stack buffer overflow vulnerability." },
      helpUri: "https://cwe.mitre.org/data/definitions/121.html",
      fullDescription: { 
        text: "Stack buffer overflow occurs when a program writes beyond the bounds of a stack-allocated buffer." 
      }
    },
    result: {
      message: { 
        text: `Stack buffer overflow vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
        markdown: `**[Critical] Stack Buffer Overflow detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-121",
      level: "error",
      kind: "fail",
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: encodedUri },
          region: {
            startLine: location.declarationLine,
            startColumn: 1,
            endLine: location.declarationLine,
            endColumn: 1000
          }
        }
      }],
      codeFlows: [createCodeFlow([
        {
          file: location.declarationFile,
          line: location.bufferDeclarationLine,
          message: "1. Identify stack buffer declaration 📌"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "2. Detect unsafe write operation ⚠️"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "3. Compile with ASan: -fsanitize=address -fstack-protector 🛠️"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "4. Check ASan report for 'stack-buffer-overflow' warnings 📋"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "5. Fix: Use bounds-checked functions like `strncpy` or validate input size ✅"
        }
      ])],
      stacks: [createStackFrame([
        {
          file: location.declarationFile,
          line: location.bufferDeclarationLine,
          message: bufferSnippet
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: vulnSnippet
        }
      ])]
    }
  };
}
