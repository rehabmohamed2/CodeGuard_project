export interface VulnerabilityLocation {
    type: string;
    declarationFile: string;
    declarationLine: number;
    declarationColumn: number;
    [key: string]: any; // Allow checker-specific fields
  }
  
  export interface Checker {
    name: string;
    testInput: string;
    asanOptions: string;
    parse: (output: string) => VulnerabilityLocation | null;
    generateSarif: (location: VulnerabilityLocation) => any;
  }