import { useCallback, useMemo, useState } from 'react'
import { sanitizeForHistory, SEED_HISTORY } from '../data/mockResults'
import { ScanContext } from './scanContext'

/**
 * Session-only scan state: the current result and the in-memory history
 * list. Nothing is written to a server, database, or local storage.
 */

let historyCounter = 0

export function ScanProvider({ children }) {
  const [currentResult, setCurrentResult] = useState(null)
  const [history, setHistory] = useState(SEED_HISTORY)

  const addHistoryEntry = useCallback((result) => {
    const entry = {
      id: `scan-${Date.now()}-${historyCounter++}`,
      url: sanitizeForHistory(result.url),
      domain: result.domain,
      risk_level: result.risk_level,
      risk_score: result.risk_score,
      scanned_at: result.scanned_at,
      record_type: 'scan',
      result,
    }
    setHistory((prev) => [entry, ...prev])
    return entry
  }, [])

  const value = useMemo(
    () => ({ currentResult, setCurrentResult, history, addHistoryEntry }),
    [currentResult, history, addHistoryEntry],
  )

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>
}
