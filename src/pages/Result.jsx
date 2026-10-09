import { useCallback } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import ResultDashboard from '../components/ResultDashboard'
import { useScan } from '../state/scanContext'

/**
 * Results page. Renders the current analysis report (the shared dashboard
 * covers the low-, medium-, and high-risk demonstrations plus unknown
 * results). Without a result to show, it returns to the landing page so no
 * fake report is ever displayed.
 */
export default function Result() {
  const { currentResult, setCurrentResult } = useScan()
  const navigate = useNavigate()

  const handleNewScan = useCallback(() => {
    setCurrentResult(null)
    navigate('/')
  }, [navigate, setCurrentResult])

  if (!currentResult) {
    return <Navigate to="/" replace />
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <ResultDashboard result={currentResult} onNewScan={handleNewScan} />
    </div>
  )
}
