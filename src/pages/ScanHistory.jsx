import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, Inbox } from 'lucide-react'
import RiskBadge from '../components/RiskBadge'
import { formatTimestamp } from '../components/riskStyles'
import { useScan } from '../state/scanContext'

/**
 * Scan history: an in-memory list of demonstration records plus any scans
 * performed this session. No database, no accounts, and sensitive query
 * parameters are stripped before a URL is listed.
 */
export default function ScanHistory() {
  const { history, setCurrentResult } = useScan()
  const navigate = useNavigate()

  const viewResult = useCallback(
    (record) => {
      setCurrentResult(record.result)
      navigate('/result')
    },
    [navigate, setCurrentResult],
  )

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="animate-rise mb-6 flex flex-col gap-2">
        <h1 className="section-title">Scan history</h1>
        <p className="max-w-2xl text-sm text-muted">
          Previous scans from this session — stored in memory only.
        </p>
      </div>

      {history.length === 0 ? (
        <div className="card flex flex-col items-center gap-3 border-dashed p-10 text-center">
          <Inbox size={28} className="text-muted" aria-hidden="true" />
          <p className="text-sm font-semibold text-ink">No scans yet</p>
          <p className="max-w-sm text-sm text-muted">
            Run your first analysis from the home page and it will appear here.
          </p>
        </div>
      ) : (
        <>
          {/* Desktop: table */}
          <div className="card animate-rise anim-delay-1 hidden overflow-hidden md:block">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-line bg-canvas text-xs font-bold uppercase tracking-wide text-muted">
                  <th scope="col" className="px-5 py-3">
                    URL
                  </th>
                  <th scope="col" className="px-5 py-3">
                    Risk category
                  </th>
                  <th scope="col" className="px-5 py-3">
                    Score
                  </th>
                  <th scope="col" className="px-5 py-3">
                    Scanned
                  </th>
                  <th scope="col" className="px-5 py-3 text-right">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {history.map((record) => (
                  <tr key={record.id} className="transition-colors duration-200 hover:bg-canvas/70">
                    <td className="max-w-xs px-5 py-4">
                      <p className="truncate font-mono text-[13px] font-medium text-ink" title={record.url}>
                        {record.url}
                      </p>
                      <p className="mt-0.5 text-xs text-muted">{record.domain}</p>
                    </td>
                    <td className="px-5 py-4">
                      <RiskBadge level={record.risk_level} size="sm" />
                    </td>
                    <td className="tabular px-5 py-4 font-semibold text-ink">
                      {typeof record.risk_score === 'number'
                        ? `${record.risk_score}/100`
                        : '—'}
                    </td>
                    <td className="whitespace-nowrap px-5 py-4 text-xs text-muted">
                      {formatTimestamp(record.scanned_at)}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <button
                        type="button"
                        onClick={() => viewResult(record)}
                        className="btn-secondary px-3.5 py-2 text-xs"
                      >
                        <Eye size={14} aria-hidden="true" />
                        View Result
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile: cards */}
          <ul className="stagger-children space-y-3 md:hidden">
            {history.map((record) => (
              <li key={record.id} className="card p-4 transition-shadow duration-200 hover:shadow-md">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[13px] font-medium text-ink" title={record.url}>
                      {record.url}
                    </p>
                    <p className="mt-1 text-xs text-muted">{record.domain}</p>
                  </div>
                  <RiskBadge level={record.risk_level} size="sm" />
                </div>
                <div className="mt-3 flex items-center justify-between gap-3 border-t border-line pt-3">
                  <div className="text-xs text-muted">
                    <span className="tabular font-semibold text-ink">
                      {typeof record.risk_score === 'number'
                        ? `${record.risk_score}/100`
                        : '—'}
                    </span>
                    <span className="mx-1.5">·</span>
                    {formatTimestamp(record.scanned_at)}
                  </div>
                  <button
                    type="button"
                    onClick={() => viewResult(record)}
                    className="btn-secondary px-3.5 py-1.5 text-xs"
                  >
                    <Eye size={14} aria-hidden="true" />
                    View Result
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

    </div>
  )
}
