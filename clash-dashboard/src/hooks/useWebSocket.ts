import { useEffect, useState } from 'react';

export type ReadyState = 'CONNECTING' | 'OPEN' | 'CLOSING' | 'CLOSED';

interface UseWebSocketReturn<T> {
  lastMessage: T | null;
  readyState: ReadyState;
}

interface MessageState<T> {
  url: string | null;
  message: T | null;
}

export function useWebSocket<T = unknown>(url: string | null): UseWebSocketReturn<T> {
  const [messageState, setMessageState] = useState<MessageState<T>>({
    url: null,
    message: null,
  });
  const [readyState, setReadyState] = useState<ReadyState>('CLOSED');

  useEffect(() => {
    setMessageState({ url, message: null });
    if (!url) {
      setReadyState('CLOSED');
      return;
    }

    let active = true;
    let retryCount = 0;
    let socket: WebSocket | null = null;
    let retryTimeout: ReturnType<typeof setTimeout> | null = null;

    const scheduleReconnect = () => {
      if (!active) return;
      const delay = Math.min(1000 * 2 ** retryCount, 30000);
      retryCount = Math.min(retryCount + 1, 8);
      retryTimeout = setTimeout(connect, delay);
    };

    const connect = () => {
      if (!active) return;
      setReadyState('CONNECTING');

      try {
        socket = new WebSocket(url);
      } catch {
        setReadyState('CLOSED');
        scheduleReconnect();
        return;
      }

      const currentSocket = socket;
      currentSocket.onopen = () => {
        if (!active || socket !== currentSocket) return;
        setReadyState('OPEN');
        retryCount = 0;
      };

      currentSocket.onmessage = (event) => {
        if (!active || socket !== currentSocket) return;
        try {
          setMessageState({ url, message: JSON.parse(event.data) as T });
        } catch {
          // Ignore malformed messages and keep the connection alive.
        }
      };

      currentSocket.onclose = () => {
        if (!active || socket !== currentSocket) return;
        socket = null;
        setReadyState('CLOSED');
        scheduleReconnect();
      };

      currentSocket.onerror = () => currentSocket.close();
    };

    connect();

    return () => {
      active = false;
      if (retryTimeout) clearTimeout(retryTimeout);
      const previousSocket = socket;
      socket = null;
      previousSocket?.close();
    };
  }, [url]);

  return {
    lastMessage: messageState.url === url ? messageState.message : null,
    readyState,
  };
}
