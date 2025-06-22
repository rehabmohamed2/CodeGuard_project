import { Checker } from '../../types';
import { parse } from './parser';
import { generateSarif } from './sarif';

export const useDoubleFreeChecker: Checker = {
  name: 'Double Free',
  testInput: '', // No specific test input needed for UAF
  asanOptions: 'halt_on_error=0,detect_stack_use_after_return=1,detect_leaks=1',
  parse,
  generateSarif
};