import { motorBridge, type BridgeResult } from '../bridge'
import { invalidate } from './shared'

/** Whitelist from a threats/config response: null if the response has no config object. */
export function whitelistOf(cloud: BridgeResult): string[] | null {
  if (!cloud.ok || !cloud.data || typeof cloud.data !== 'object') return null
  const wl = (cloud.data as Record<string, unknown>).whitelist_ips
  return Array.isArray(wl) ? wl.map(String) : []
}

export const saveWhitelist = (next: string[]) => motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })

/** Read-modify-write on a fresh copy so a cached list never overwrites a newer one. */
export async function editWhitelist(add: string[] = [], remove: string[] = []): Promise<BridgeResult> {
  invalidate('cloud:threats/config')
  const current = whitelistOf(await motorBridge.cloud('GET', 'threats/config')) ?? []
  return saveWhitelist(Array.from(new Set([...current.filter((ip) => !remove.includes(ip)), ...add])))
}
