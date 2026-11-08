import { useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { queryKeys } from '@/lib/queryKeys';
import { captureApiSettings } from '@/lib/api/client';
import type { ApiSettingsSnapshot } from '@/lib/api/client';
import { clearTemporaryNetworkPathPreference, updateNetworkPathPreference } from '@/lib/api/network';
import type { EffectiveNetworkPaths, PathPreferencePriority, PathPreferenceView } from '@/lib/api/types/network';
import { formatTimestamp, isPreferenceInterface, phaseLabel, priorityKey, samePriority } from '@/features/network/networkUtils';
import { ErrorNotice } from './ErrorNotice';

export function PathPreferenceEditor({
  paths,
  preference,
}: {
  paths: EffectiveNetworkPaths | undefined;
  preference: UseQueryResult<PathPreferenceView, Error>;
}) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<PathPreferencePriority[]>([]);
  const [lifetime, setLifetime] = useState('unchanged');
  const [candidateKey, setCandidateKey] = useState('');
  const syncedPreference = useRef('');
  type PreferenceQueryKey = ReturnType<typeof queryKeys.network.pathPreference>;

  useEffect(() => {
    const current = preference.data;
    if (!current) return;
    const versionKey = JSON.stringify([
      current.policyVersion,
      current.source,
      current.createdAtMs,
      current.expiresAtMs,
      current.priority,
    ]);
    if (syncedPreference.current === versionKey) return;
    syncedPreference.current = versionKey;
    setDraft(current.priority);
    setLifetime('unchanged');
  }, [preference.data]);

  const save = useMutation({
    mutationFn: ({ priority, ttlMs, settings }: {
      priority: PathPreferencePriority[];
      ttlMs?: number;
      queryKey: PreferenceQueryKey;
      settings: ApiSettingsSnapshot;
    }) => updateNetworkPathPreference(priority, ttlMs, settings),
    onSuccess: (data: PathPreferenceView, variables) => {
      queryClient.setQueryData(variables.queryKey, data);
    },
  });
  const clearTemporary = useMutation({
    mutationFn: ({ settings }: { queryKey: PreferenceQueryKey; settings: ApiSettingsSnapshot }) =>
      clearTemporaryNetworkPathPreference(settings),
    onSuccess: (data: PathPreferenceView, variables) => {
      queryClient.setQueryData(variables.queryKey, data);
    },
  });

  const priorityOptions = new Map<string, PathPreferencePriority>();
  for (const path of paths?.paths ?? []) {
    if (!isPreferenceInterface(path.interfaceKind)) continue;
    const priority = {
      interface: path.interfaceKind,
      family: path.family,
    };
    priorityOptions.set(priorityKey(priority), priority);
  }
  const addableOptions = [...priorityOptions.values()].filter(
    (option) => !draft.some((entry) => samePriority(entry, option)),
  );
  const isTemporary = preference.data?.source === 'temporaryOverride';
  const busy = save.isPending || clearTemporary.isPending;
  const mutationError = save.error ?? clearTemporary.error;
  const draftMatchesCurrent = preference.data
    ? JSON.stringify(draft) === JSON.stringify(preference.data.priority)
    : false;

  function applyPreference(priority: PathPreferencePriority[]) {
    const ttlMs = lifetime === 'runtime'
      ? undefined
      : lifetime === 'unchanged'
        ? (preference.data?.expiresAtMs == null
          ? undefined
          : Math.max(1000, Math.min(86_400_000, preference.data.expiresAtMs - Date.now())))
        : Number(lifetime);
    save.mutate({
      priority,
      ttlMs,
      queryKey: queryKeys.network.pathPreference(),
      settings: captureApiSettings(),
    });
  }

  function movePriority(index: number, offset: -1 | 1) {
    setDraft((current) => {
      const targetIndex = index + offset;
      if (targetIndex < 0 || targetIndex >= current.length) return current;
      const next = [...current];
      [next[index], next[targetIndex]] = [next[targetIndex], next[index]];
      return next;
    });
  }

  return (
    <section className="liquid-glass-card rounded-xl overflow-hidden">
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
        <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Path preference</h2>
        <p className="mt-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
          Order interface type and address-family preferences for new connections that use automatic path selection. This does not change system routes or override a required interface.
        </p>
      </div>

      {preference.isLoading ? (
        <div className="px-4 py-5 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading path preference…</div>
      ) : preference.isError ? (
        <div className="p-4"><ErrorNotice message={preference.error instanceof Error ? preference.error.message : 'Could not load path preference.'} /></div>
      ) : preference.data ? (
        <div className="space-y-4 p-4">
          {!preference.data.automaticSupported && (
            <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
              Path preferences are unavailable because this platform does not report automatic network paths.
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={isTemporary ? 'amber' : 'gray'}>{isTemporary ? 'Temporary override' : 'Runtime preference'}</Badge>
            <span className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Policy version {preference.data.policyVersion}
              {preference.data.expiresAtMs == null ? ' · cleared when the core exits' : ` · expires ${formatTimestamp(preference.data.expiresAtMs)}`}
            </span>
          </div>

          {draft.length === 0 ? (
            <div className="rounded-lg px-3 py-2 text-[13px]" style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}>
              No explicit preference is set; the core uses its default path-selection rules.
            </div>
          ) : (
            <ol className="space-y-2">
              {draft.map((priority, index) => {
                const observed = (paths?.paths ?? []).some(
                  (path) => path.interfaceKind === priority.interface && path.family === priority.family,
                );
                return (
                  <li key={priorityKey(priority)} className="flex flex-wrap items-center justify-between gap-2 rounded-lg px-3 py-2" style={{ background: 'var(--color-fill-subtle)' }}>
                    <div className="flex items-center gap-2 text-[13px]" style={{ color: 'var(--color-text-primary)' }}>
                      <span className="font-semibold">{index + 1}.</span>
                      <span>{phaseLabel(priority.interface)} · {phaseLabel(priority.family)}</span>
                      {!observed && <Badge variant="gray">Not currently observed</Badge>}
                    </div>
                    <div className="flex gap-1">
                      <Button size="xs" variant="outline" aria-label={`Move preference ${index + 1} up`} disabled={busy || index === 0} onClick={() => movePriority(index, -1)}>↑</Button>
                      <Button size="xs" variant="outline" aria-label={`Move preference ${index + 1} down`} disabled={busy || index === draft.length - 1} onClick={() => movePriority(index, 1)}>↓</Button>
                      <Button size="xs" variant="outline" aria-label={`Remove preference ${index + 1}`} disabled={busy} onClick={() => setDraft((current) => current.filter((_, itemIndex) => itemIndex !== index))}>Remove</Button>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}

          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-52 flex-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Add an observed path
              <select
                value={candidateKey}
                onChange={(event) => setCandidateKey(event.target.value)}
                disabled={!preference.data.automaticSupported || addableOptions.length === 0 || busy}
                className="mt-1 w-full rounded-lg border px-3 py-2 text-[13px]"
                style={{ background: 'var(--color-input-bg)', borderColor: 'var(--color-separator)', color: 'var(--color-text-primary)' }}
              >
                <option value="">Select interface type and family…</option>
                {addableOptions.map((option) => <option key={priorityKey(option)} value={priorityKey(option)}>{phaseLabel(option.interface)} · {phaseLabel(option.family)}</option>)}
              </select>
            </label>
            <Button
              variant="outline"
              disabled={!candidateKey || busy || !preference.data.automaticSupported}
              onClick={() => {
                const selected = priorityOptions.get(candidateKey);
                if (selected && !draft.some((entry) => samePriority(entry, selected))) setDraft((current) => [...current, selected]);
                setCandidateKey('');
              }}
            >Add preference</Button>

            <label className="min-w-52 flex-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Lifetime
              <select
                value={lifetime}
                onChange={(event) => setLifetime(event.target.value)}
                disabled={!preference.data.automaticSupported || busy}
                className="mt-1 w-full rounded-lg border px-3 py-2 text-[13px]"
                style={{ background: 'var(--color-input-bg)', borderColor: 'var(--color-separator)', color: 'var(--color-text-primary)' }}
              >
                <option value="unchanged">Keep current lifetime</option>
                <option value="runtime">Until the core exits</option>
                <option value="900000">15 minutes</option>
                <option value="3600000">1 hour</option>
                <option value="86400000">24 hours</option>
              </select>
            </label>
          </div>

          <p className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
            Preferences apply to new connections. Existing connections are not moved, and runtime preferences are not written to the YAML configuration.
          </p>
          {mutationError && (
            <ErrorNotice message={mutationError instanceof Error ? mutationError.message : 'Could not update path preference.'} />
          )}
          {(save.isSuccess || clearTemporary.isSuccess) && !mutationError && lifetime === 'unchanged' && draftMatchesCurrent && (
            <div role="status" className="text-[13px]" style={{ color: '#34a853' }}>Path preference updated.</div>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            {isTemporary && (
              <Button variant="outline" disabled={busy} onClick={() => clearTemporary.mutate({
                queryKey: queryKeys.network.pathPreference(),
                settings: captureApiSettings(),
              })}>
                Clear temporary override
              </Button>
            )}
            <Button variant="outline" disabled={busy || !preference.data.automaticSupported} onClick={() => save.mutate({
              priority: [],
              queryKey: queryKeys.network.pathPreference(),
              settings: captureApiSettings(),
            })}>
              Use core default
            </Button>
            <Button disabled={busy || !preference.data.automaticSupported} onClick={() => applyPreference(draft)}>
              {busy ? 'Applying…' : 'Apply preference'}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
