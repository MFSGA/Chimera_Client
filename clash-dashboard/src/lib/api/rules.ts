import { request } from './client';
import type { Rule } from './types';

// Rules
export const getRules = () => request<{ rules: Rule[] }>('/rules');
