import { useEffect, useMemo, useState } from 'react';
import { useWebSocket } from './useWebSocket';
import { getWsUrl } from '../lib/api/client';
import type { TrafficData } from '../lib/api/types/realtime';

const HISTORY_LENGTH = 60;

interface TrafficHistory {
  up: number[];
  down: number[];
  timestamps: number[];
}

interface UseTrafficReturn {
  history: TrafficHistory;
  current: TrafficData;
}

interface TrafficState extends UseTrafficReturn {
  url: string;
}

function createEmptyHistory(): TrafficHistory {
  const now = Date.now() / 1000;
  return {
    up: new Array(HISTORY_LENGTH).fill(0),
    down: new Array(HISTORY_LENGTH).fill(0),
    timestamps: Array.from(
      { length: HISTORY_LENGTH },
      (_, i) => now - (HISTORY_LENGTH - 1 - i),
    ),
  };
}

function createEmptyCurrent(): TrafficData {
  return { up: 0, down: 0, upTotal: 0, downTotal: 0 };
}

export function useTraffic(): UseTrafficReturn {
  const url = getWsUrl('/ws/traffic');
  const { lastMessage } = useWebSocket<TrafficData>(url);

  const emptyState = useMemo<TrafficState>(
    () => ({ url, history: createEmptyHistory(), current: createEmptyCurrent() }),
    [url],
  );
  const [state, setState] = useState<TrafficState>(emptyState);

  useEffect(() => {
    if (!lastMessage) return;
    setState((prev) => {
      const history = prev.url === url ? prev.history : createEmptyHistory();
      const now = Date.now() / 1000;
      return {
        url,
        current: lastMessage,
        history: {
          up: [...history.up.slice(1), lastMessage.up],
          down: [...history.down.slice(1), lastMessage.down],
          timestamps: [...history.timestamps.slice(1), now],
        },
      };
    });
  }, [lastMessage, url]);

  useEffect(() => {
    setState(emptyState);
  }, [emptyState]);

  const visibleState = state.url === url ? state : emptyState;
  return { history: visibleState.history, current: visibleState.current };
}
