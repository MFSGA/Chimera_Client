import { useSyncExternalStore } from 'react';
import { getSettingsRevision, subscribeToSettings } from '../lib/settings';

export function useApiSettingsRevision(): number {
  return useSyncExternalStore(subscribeToSettings, getSettingsRevision, getSettingsRevision);
}
