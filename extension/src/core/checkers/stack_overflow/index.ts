import { Checker } from '../../types';
import { parse } from './parser';
import { generateSarif } from './sarif';

export const stackOverflowChecker: Checker = {
  name: 'Stack Buffer Overflow',
  testInput: 'A'.repeat(100),
  asanOptions: 'detect_stack_use_after_return=1',
  parse,
  generateSarif
};