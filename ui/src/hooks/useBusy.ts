import { useCallback, useState } from 'react'

/** Busy flag + runner: `run(fn)` sets busy while fn runs and always clears it (replaces try/finally blocks). */
export function useBusy(initial = false) {
  const [busy, setBusy] = useState(initial)
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T> => {
    setBusy(true)
    try {
      return await fn()
    } finally {
      setBusy(false)
    }
  }, [])
  return [busy, run, setBusy] as const
}
