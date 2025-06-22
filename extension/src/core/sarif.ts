import * as fs from 'fs';
import * as path from 'path';

/**
 * Creates a base SARIF report structure.
 */
export function createBaseSarifReport() {
  return {
    $schema: "http://json.schemastore.org/sarif-2.1.0",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Secure Code Analyzer",
          informationUri: "https://your-extension-docs.com",
          rules: [] as any[]
        }
      },
      results: [] as any[]
    }]
  };
}

/**
 * Merges SARIF data from different checkers into a single report.
 */
export function mergeSarifData(baseReport: any, checkerData: any[]) {
  checkerData.forEach(data => {
    // Merge rules
    if (data.rule) {
      baseReport.runs[0].tool.driver.rules.push(data.rule);
    }
    // Merge results with full details
    if (data.result) {
      baseReport.runs[0].results.push({
        ...data.result,
        codeFlows: data.codeFlows || [],
        stacks: data.stacks || [],
        relatedLocations: data.relatedLocations || []
      });
    }
  });
}

/**
 * Encodes a file path as a file URI.
 * This implementation uses Node's path.resolve and constructs the URI manually.
 */
export function encodeSarifUri(filePath: string): string {
  const absolutePath = path.resolve(filePath).replace(/\\/g, '/');
  const encodedPath = absolutePath.replace(/#/g, '%23');
  
  // For Unix-like paths (starting with "/"), use "file://"
  // For Windows paths (e.g., "C:/"), use "file:///"
  return absolutePath.startsWith('/') 
    ? `file://${encodedPath}` 
    : `file:///${encodedPath}`;
}

/**
 * Retrieves a code snippet from a file given a line number.
 * Uses process.cwd() as the workspace root.
 */
export function getCodeSnippet(lineNumber: number, filePath: string): string {
  const fullPath = path.resolve(filePath);
  try {
    const document = fs.readFileSync(fullPath, 'utf-8');
    return document.split('\n')[lineNumber - 1]?.trim() || '';
  } catch (error) {
    return 'Unable to retrieve code snippet';
  }
}

/**
 * Creates a SARIF code flow from a list of locations.
 */
export function createCodeFlow(locations: Array<{
  file: string;
  line: number;
  message: string;
}>): any {
  return {
    threadFlows: [{
      locations: locations.map(loc => ({
        location: {
          physicalLocation: {
            artifactLocation: { uri: encodeSarifUri(loc.file) },
            region: { startLine: loc.line }
          },
          message: { text: loc.message }
        }
      }))
    }]
  };
}

/**
 * Creates a SARIF stack frame from a list of frames.
 */
export function createStackFrame(frames: Array<{
  file: string;
  line: number;
  message: string;
}>): any {
  return {
    message: { text: "Vulnerability stack trace: " },
    frames: frames.map(frame => ({
      location: {
        physicalLocation: {
          artifactLocation: { uri: encodeSarifUri(frame.file) },
          region: {
            startLine: frame.line,
            startColumn: 1,
            endLine: frame.line,
            endColumn: 1000
          }
        },
        message: { text: frame.message }
      }
    }))
  };
}
