import { request } from './client';
import type { Capabilities, MemoryData, Version } from './types';

// Version
export const getVersion = () => request<Version>('/version');
export const getCapabilities = () => request<Capabilities>('/capabilities');

// Memory
export const getMemory = () => request<MemoryData>('/memory');

// Restart
export const restart = () => request<void>('/restart', { method: 'POST' });
