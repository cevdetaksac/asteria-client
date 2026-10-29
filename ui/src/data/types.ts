/** Shared UI data types (C4). */
export type HardenCheck = {
  id?: string
  label?: string
  ok?: boolean | null
  detail?: string
  fixable?: boolean
}

export type IpRow = {
  ip: string
  services?: string[]
  attempts?: number
  score?: number
  reason?: string
  last_seen?: number
  status?: string
}
