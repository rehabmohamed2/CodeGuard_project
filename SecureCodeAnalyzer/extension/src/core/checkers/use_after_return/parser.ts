import { VulnerabilityLocation } from '../../types';

export function parse(output: string): VulnerabilityLocation | null {
  const regex = /==\d+==ERROR: AddressSanitizer: (\S+)[\s\S]*?#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^()\s]+):(\d+):(\d+)[\s\S]*?'[^']+'\s+\(line\s+(\d+)\)/;
  const match = output.match(regex);

  if (!match || match[1] != 'stack-use-after-return') return null;

  return {
    type: match[1],
    declarationFunction: match[2],
    declarationFile: match[3],
    declarationLine: parseInt(match[4], 10),
    declarationColumn: parseInt(match[5], 10),
    bufferDeclarationLine: parseInt(match[6], 10)
  };
}