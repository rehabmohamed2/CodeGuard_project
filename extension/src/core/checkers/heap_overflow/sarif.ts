import * as path from 'path';
import { VulnerabilityLocation } from '../../types';
import { encodeSarifUri, createCodeFlow, createStackFrame, getCodeSnippet } from '../../sarif';

export function generateSarif(location: VulnerabilityLocation) {
  const encodedVulnUri = encodeSarifUri(location.declarationFile);

  // Get code snippets
  const bufferSnippet = getCodeSnippet(location.allocationLine, location.allocationFile);
  const vulnSnippet = getCodeSnippet(location.declarationLine, location.declarationFile);

  return {
    rule: {
      id: "CWE-122",
      name: "Heap-based Buffer Overflow",
      shortDescription: {
        text: "Detects Heap-based buffer overflow vulnerability where data is written outside the allocated buffer bounds."
      },
      helpUri: "https://cwe.mitre.org/data/definitions/122.html",
      fullDescription: {
        text: "A heap buffer overflow occurs when a program writes more data to a block of memory than allocated."
      }
    },
    result: {
      message: { 
        text: `Heap Buffer Overflow vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
        markdown: `**[Critical] Heap Buffer Overflow detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-122",
      level: "error",
      kind: "fail",
      baselineState: "new",
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
          message: "1. Identify heap buffer declaration 📌"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "2. Provide oversized input to trigger overflow 📝"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "3. Compile with ASan: -fsanitize=address -fstack-protector 🛠"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "4. Check ASan report for 'heap-buffer-overflow' warnings 📋"
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: "5. Fix the issue by using std::vector with bounds-checked access Or validate write operations match allocation size ✅"
        }
      ])],
      stacks: [createStackFrame([
        {
          file: location.allocationFile,
          line: location.allocationLine,
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