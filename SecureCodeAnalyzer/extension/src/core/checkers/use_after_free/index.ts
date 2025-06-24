import { Checker } from '../../types';
import { parse } from './parser';
import { generateSarif } from './sarif';

export const useAfterFreeChecker: Checker = {
  name: 'Use After Free',
  testInput: '', // No specific test input needed for UAF
  asanOptions: 'detect_stack_use_after_return=1,halt_on_error=0',
  parse,
  generateSarif
};