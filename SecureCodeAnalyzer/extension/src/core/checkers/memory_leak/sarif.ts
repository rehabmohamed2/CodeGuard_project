import * as path from 'path';
import { VulnerabilityLocation } from '../../types';
import { encodeSarifUri, createCodeFlow, createStackFrame, getCodeSnippet } from '../../sarif';

export function generateSarif(location: VulnerabilityLocation) {
  
  // Encode URI properly for SARIF compatibility
  const encodedUri = encodeSarifUri(location.declarationFile);
    
  // Get code snippets
  const allocationSnippet = getCodeSnippet(location.declarationLine, location.declarationFile);

  return {
    rule: {
      id: "CWE-401",
      name: "Memory Leak",
      shortDescription: { text: "Detects unreleased memory allocations." },
      helpUri: "https://cwe.mitre.org/data/definitions/401.html",
      fullDescription: {
        text: "Memory leak occurs when a program fails to release allocated memory, causing gradual memory consumption."
      }
    },
    result: {
      message: { 
        text: `Memory leak vulnerability detected in ${path.basename(location.declarationFile)} in [ ${location.declarationFunction}] function`,
        markdown: `**[Critical] Memory leak detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-401",
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
          line: location.declarationLine,
          message: `1. Memory allocation point 📌`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `2. Missing corresponding deallocation ⚠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `3. Compile with ASan: -fsanitize=address 🛠`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `4. Check ASan report for 'detected memory leaks' 📋`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `5. Fix: Add missing free/delete or use smart pointers ✅`
        }
      ])],
      stacks: [createStackFrame([
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `Memory allocated at line ${location.declarationLine}:\n${allocationSnippet}\n` + `Leaked ${location.numberOfBytesLeaked} bytes`
        }
      ])]
    }
  };
}