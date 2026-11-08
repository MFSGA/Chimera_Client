export const getApiUrl = () => localStorage.getItem('clash-api-url') || window.location.origin;

let settingsRevision = 0;
const settingsListeners = new Set<() => void>();

export const subscribeToSettings = (listener: () => void) => {
  settingsListeners.add(listener);
  return () => settingsListeners.delete(listener);
};

export const getSettingsRevision = () => settingsRevision;

function notifySettingsChanged() {
  settingsRevision += 1;
  settingsListeners.forEach((listener) => listener());
}

if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key === 'clash-api-url' || event.key === 'clash-api-secret' || event.key === null) {
      notifySettingsChanged();
    }
  });
}

export const getSecret = () => {
  const persisted = localStorage.getItem('clash-api-secret');
  if (persisted !== null) {
    return persisted;
  }

  const legacySessionSecret = sessionStorage.getItem('clash-api-secret');
  if (legacySessionSecret !== null) {
    // lgtm[js/clear-text-storage-of-sensitive-data]
    // Intentional: persist LAN dashboard credentials across browser restarts.
    // This secret stays on the current device and should only be used on trusted hosts.
    localStorage.setItem('clash-api-secret', legacySessionSecret);
    return legacySessionSecret;
  }

  return '';
};
export const setApiSettings = (url: string, secret: string) => {
  localStorage.setItem('clash-api-url', url);
  // lgtm[js/clear-text-storage-of-sensitive-data]
  // Intentional: persist LAN dashboard credentials across browser restarts.
  // This secret stays on the current device and should only be used on trusted hosts.
  localStorage.setItem('clash-api-secret', secret);
  sessionStorage.removeItem('clash-api-secret');
  notifySettingsChanged();
};
