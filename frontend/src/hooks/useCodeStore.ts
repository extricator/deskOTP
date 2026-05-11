// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EventsOn } from "../../wailsjs/runtime/runtime";
import { GetCodes, GetEntries } from "../../wailsjs/go/main/App";
import { CodePayload, CodeTickPayload, EntryMetadata } from "../types";

// useCodeStore subscribes to both codes:tick and entries:changed events.
// Merges them by id into a unified CodePayload[] that components consume unchanged.
// On mount, pulls codes via GetCodes() and metadata via GetEntries() separately,
// since GetCodes() only returns code-rotating fields (id, code, remaining, period, type)
// after the CodePayload shrink in the Go backend.
export function useCodeStore(): {
  entries: CodePayload[];
  ready: boolean;
  resetReady: () => void;
} {
  // Internal maps keyed by entry id for O(1) merge
  const metadataRef = useRef<Map<string, EntryMetadata>>(new Map());
  const codesRef = useRef<Map<string, CodeTickPayload>>(new Map());
  const [entries, setEntries] = useState<CodePayload[]>([]);
  const [ready, setReady] = useState(false);

  // Merge function: combines metadata + codes into CodePayload[]
  const merge = useCallback(() => {
    const metadata = metadataRef.current;
    const codes = codesRef.current;
    const merged: CodePayload[] = [];
    for (const [, m] of metadata) {
      const c = codes.get(m.id);
      merged.push({
        id: m.id,
        name: m.name,
        issuer: m.issuer,
        group: m.group,
        icon: m.icon,
        usageCount: m.usageCount,
        type: m.type,
        code: c?.code ?? "",
        remaining: c?.remaining ?? 0,
        period: c?.period ?? 30,
      });
    }
    setEntries(merged);
  }, []);

  useEffect(() => {
    // Pull initial data — call both GetCodes() and GetEntries() in parallel.
    // GetCodes() returns shrunk CodeTickPayload[] (id, code, remaining, period, type).
    // GetEntries() returns EntryMetadata[] (id, name, issuer, group, icon, usageCount, type).
    // Together they bootstrap both maps for a complete initial render.
    Promise.all([GetCodes(), GetEntries()])
      .then(([codesData, metaData]) => {
        const codes = codesData ?? [];
        const meta = metaData ?? [];

        const mMap = new Map<string, EntryMetadata>();
        for (const item of meta) {
          mMap.set(item.id, item);
        }

        const cMap = new Map<string, CodeTickPayload>();
        for (const item of codes) {
          cMap.set(item.id, item);
        }

        metadataRef.current = mMap;
        codesRef.current = cMap;

        // Build merged entries for initial render
        const merged: CodePayload[] = [];
        for (const [, m] of mMap) {
          const c = cMap.get(m.id);
          merged.push({
            id: m.id,
            name: m.name,
            issuer: m.issuer,
            group: m.group,
            icon: m.icon,
            usageCount: m.usageCount,
            type: m.type,
            code: c?.code ?? "",
            remaining: c?.remaining ?? 0,
            period: c?.period ?? 30,
          });
        }
        setEntries(merged);
        setReady(true);
      })
      .catch(() => {
        setReady(true);
      });

    // Subscribe to codes:tick — updates code/remaining/period only
    const unlistenCodes = EventsOn("codes:tick", (data: CodeTickPayload[]) => {
      const items = data ?? [];
      const cMap = new Map<string, CodeTickPayload>();
      for (const item of items) {
        cMap.set(item.id, item);
      }
      codesRef.current = cMap;
      // If tick carries new IDs not in metadata (e.g., after import where tick arrives first),
      // add placeholder metadata from codes so they appear in the list.
      const mMap = metadataRef.current;
      for (const item of items) {
        if (!mMap.has(item.id)) {
          mMap.set(item.id, { id: item.id, name: "", issuer: "", group: "", icon: "", usageCount: 0, type: item.type });
        }
      }
      // Remove entries from metadata that no longer exist in codes (deletion)
      for (const id of mMap.keys()) {
        if (!cMap.has(id)) {
          mMap.delete(id);
        }
      }
      merge();
      setReady(true);
    });

    // Subscribe to entries:changed — updates metadata fields only
    const unlistenMetadata = EventsOn("entries:changed", (data: EntryMetadata[]) => {
      const items = data ?? [];
      const mMap = new Map<string, EntryMetadata>();
      for (const item of items) {
        mMap.set(item.id, item);
      }
      metadataRef.current = mMap;
      // Remove codes for entries that no longer exist (deletion via metadata event)
      const cMap = codesRef.current;
      for (const id of cMap.keys()) {
        if (!mMap.has(id)) {
          cMap.delete(id);
        }
      }
      merge();
    });

    return () => {
      unlistenCodes();
      unlistenMetadata();
    };
  }, [merge]);

  const resetReady = useCallback(() => {
    setReady(false);
  }, []);

  return { entries, ready, resetReady };
}
