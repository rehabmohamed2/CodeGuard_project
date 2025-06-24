import * as path from 'path';
import { VulnerabilityLocation } from '../../types';
import { encodeSarifUri, createCodeFlow, createStackFrame, getCodeSnippet } from '../../sarif';

export function generateSarif(location: VulnerabilityLocation) {
  const encodedVulnUri = encodeSarifUri(location.declarationFile);

  // Get code snippets
  const allocSnippet = getCodeSnippet(location.allocationLine, location.allocationFile);
  const freeSnippet = getCodeSnippet(location.freeLine, location.freeFile);
  const useSnippet = getCodeSnippet(location.declarationLine, location.declarationFile);

  return {
    rule: {
      id: "CWE-416",
      name: "Use After Free",
      shortDescription: { text: "Detects use of memory after it has been freed." },
      helpUri: "https://cwe.mitre.org/data/definitions/416.html",
      fullDescription: {
        text: "Use After Free occurs when a program continues to use a pointer after the memory it points to has been deallocated."
      }
    },
    result: {
      message: { 
        text: `Use After Free detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
        markdown: `**[Critical] Use After Free detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-416",
      level: "error",
      kind: "fail",
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: encodedVulnUri },
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
          file: location.allocationFile,
          line: location.allocationLine,
          message: `1. Trace memory allocation origin in ${location.allocationFunction}() 🔎`
        },
        {
          file: location.freeFile,
          line: location.freeLine,
          message: `2. Verify premature free at line ${location.freeLine} (${path.basename(location.freeFile)}) ⚠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `3. Identify invalid access after free at line ${location.declarationLine} 🕵️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `4. Reproduce with ASan: compile with -fsanitize=address 🛠`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `5. Check ASan report for 'freed by'/'accessed by' thread traces 📋`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `6. Fix: Use smart pointers (std::unique_ptr) or nullify pointer after delete ✅`
        }
      ])],
      stacks: [createStackFrame([
        {
          file: location.allocationFile,
          line: location.allocationLine,
          message: allocSnippet
        },
        {
          file: location.freeFile,
          line: location.freeLine,
          message: freeSnippet
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: useSnippet
        }
      ])]
    }
  };
}