import { Checker } from '../../types';
import { parse } from './parser';
import { generateSarif } from './sarif';

export const heapOverflowChecker: Checker = {
  name: 'Heap Buffer Overflow',
  testInput: '',
  asanOptions: 'detect_stack_use_after_return=1',
  parse,
  generateSarif
};