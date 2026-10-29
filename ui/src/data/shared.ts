/**
 * C2: shared read layer. All pages read motor/cloud state through here so the same
 * query issued by several pages (IP_TABLE, threats/config, harden status, SVC/SHARES lists)
 * is fetched once: in-flight requests are deduplicated and successful results are kept for
 * a short TTL. Any mutation invalidates the affected keys so reads after a write are fresh.
 */
import type { BridgeResult } from '../bridge'

type Entry = { at: number; value?: BridgeResult; pending?: Promise<BridgeResult> }

const cache = new Map<string, Entry>()

/** TTL (ms) per read key. Keys not listed here are never cached. */
export const READ_TTL: Record<string, number> = {
  'ipc:IP_TABLE': 4000,
  'ipc:SHARES_LIST': 15000,
  'ipc:SVC_LIST': 15000,
  'ipc:THREAT_TOP': 3000,
  'ipc:HONEYPOT_LIST': 4000,
  'cloud:threats/config': 5000,
  'harden:status': 15000,
}

/** Mutation -> read keys it makes stale. */
const INVALIDATES: Record<string, string[]> = {
  'ipc:BLOCK_IP': ['ipc:IP_TABLE', 'ipc:THREAT_TOP'],
  'ipc:UNBLOCK_IP': ['ipc:IP_TABLE', 'ipc:THREAT_TOP'],
  'ipc:CLEAR_FIREWALL': ['ipc:IP_TABLE', 'ipc:THREAT_TOP'],
  'ipc:SHARE_REMOVE': ['ipc:SHARES_LIST', 'harden:status'],
  'ipc:SVC_STOP': ['ipc:SVC_LIST', 'harden:status'],
  'ipc:HONEYPOT_START': ['ipc:HONEYPOT_LIST'],
  'ipc:HONEYPOT_STOP': ['ipc:HONEYPOT_LIST'],
  'ipc:NG_ACCEPT_SURFACE': ['harden:status'],
  'ipc:RS_UNLOCK': ['harden:status'],
  'harden:fix': ['harden:status', 'ipc:SHARES_LIST', 'ipc:SVC_LIST'],
  'cloud:threats/config': ['cloud:threats/config', 'ipc:IP_TABLE'],
}

export function invalidate(...keys: string[]): void {
  if (keys.length === 0) cache.clear()
  for (const k of keys) cache.delete(k)
}

/** Call after a mutation identified by `key` (e.g. 'ipc:BLOCK_IP'). */
export function invalidateAfter(key: string): void {
  const keys = INVALIDATES[key]
  if (keys) invalidate(...keys)
}

/** Read through the shared cache; uncached keys just run `fn`. Failures are not cached. */
export function sharedRead(key: string, fn: () => Promise<BridgeResult>): Promise<BridgeResult> {
  const ttl = READ_TTL[key]
  if (!ttl) return fn()
  const now = Date.now()
  const hit = cache.get(key)
  if (hit?.pending) return hit.pending
  if (hit?.value && now - hit.at < ttl) return Promise.resolve(hit.value)
  const pending = fn().then(
    (value) => {
      if (value && value.ok !== false) cache.set(key, { at: Date.now(), value })
      else cache.delete(key)
      return value
    },
    (err) => {
      cache.delete(key)
      throw err
    },
  )
  cache.set(key, { at: hit?.at ?? 0, value: hit?.value, pending })
  return pending
}

/** Run a mutation and invalidate what it affects, even if it fails (state may have changed). */
export async function sharedWrite(key: string, fn: () => Promise<BridgeResult>): Promise<BridgeResult> {
  try {
    return await fn()
  } finally {
    invalidateAfter(key)
  }
}
