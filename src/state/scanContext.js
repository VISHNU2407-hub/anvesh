import { createContext, useContext } from 'react'

/**
 * Session-only scan state context. Kept separate from the provider
 * component so modules can import the hook without breaking component
 * hot-reloading.
 */
export const ScanContext = createContext(null)

export function useScan() {
  const ctx = useContext(ScanContext)
  if (!ctx) throw new Error('useScan must be used inside <ScanProvider>')
  return ctx
}
