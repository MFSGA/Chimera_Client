import { request } from './client';
import type { ConnectionsData } from './types';

// Connections
export const getConnections = () => request<ConnectionsData>('/connections');
export const closeAllConnections = () => request<void>('/connections', { method: 'DELETE' });
export const closeConnection = (id: string) =>
  request<void>(`/connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
