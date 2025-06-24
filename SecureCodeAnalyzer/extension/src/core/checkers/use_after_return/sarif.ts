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
      id: "CWE-562",
      name: "Use After Return",
      shortDescription: { text: "Detects use of memory after it has been freed." },
      helpUri: "https://cwe.mitre.org/data/definitions/562.html",
      fullDescription: {
        text: "Use-after-return occurs when a program accesses stack memory through a pointer after the containing function has returned."
      }
    },
    result: {
      message: { 
        text: `Use After Return vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
        markdown: `**[Critical] Use After Return detected in ${path.basename(location.declarationFile)}**`
      },
      ruleId: "CWE-562",
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
          message: `1. Identify stack address return in function 📌`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `2. Detect invalid memory access after return ⚠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `3. Compile with ASan flags: -fsanitize=address -fsanitize-address-use-after-return=always 🛠️`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `4. Check ASan report for 'stack-use-after-return' warnings 📋`
        },
        {
          file: location.declarationFile,
          line: location.declarationLine,
          message: `5. Fix: Avoid returning stack addresses or use dynamic allocation ✅`
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