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
      id: "CWE-415",
      name: "Double Free",
      shortDescription: { text: "Detects duplicate memory deallocation attempts." },
      helpUri: "https://cwe.mitre.org/data/definitions/415.html",
      fullDescription: {
        text: "Double Free occurs when a program attempts to free memory that has already been deallocated."
      }
    },
    result: {
      message: { 
        text: `Double Free vulnerability detected in ${path.basename(location.declarationFile)} in [ ${location.declarationFunction} ] function`,
        markdown: `**[Critical] Double Free vulnerability detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-415",
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
          message: `2. First valid free at line ${location.freeLine} (${path.basename(location.freeFile)}) ✅`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `3. Duplicate free detected at line ${location.declarationLine} ⚠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `4. Verify with ASan: compile with -fsanitize=address 🛠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `5. Check ASan report for 'double-free' stack traces 📋`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `6. Fix: Use RAII patterns or track ownership with null checks ✅`
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