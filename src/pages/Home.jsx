import { useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import ErrorMessage from '../components/ErrorMessage'
import LoadingState from '../components/LoadingState'
import UrlScanner from '../components/UrlScanner'
import { useScan } from '../state/scanContext'
import {
  AnalysisError,
  FALLBACK_ERROR,
  analyzeUrl,
  validateUrl,
} from '../services/analysisApi'

/** Minimum time the analyzing animation stays on screen. */
const MIN_LOADING_MS = 2700

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Landing page: one heading, one description, and the URL scanner. No
 * result is shown before the user submits a URL.
 */
export default function Home() {
  const [url, setUrl] = useState('')
  const [phase, setPhase] = useState('idle') // 'idle' | 'loading' | 'error'
  const [validationError, setValidationError] = useState(null)
  const [serviceError, setServiceError] = useState(null)

  const navigate = useNavigate()
  const { setCurrentResult, addHistoryEntry } = useScan()

  const handleUrlChange = useCallback((value) => {
    setUrl(value)
    setValidationError(null)
    setServiceError(null)
    setPhase((p) => (p === 'error' ? 'idle' : p))
  }, [])

  const handleClear = useCallback(() => {
    setUrl('')
    setValidationError(null)
    setServiceError(null)
    setPhase('idle')
  }, [])

  const runScan = useCallback(
    async (rawUrl) => {
      const validation = validateUrl(rawUrl)
      if (!validation.ok) {
        setValidationError(validation)
        setServiceError(null)
        setPhase('idle')
        return
      }

      setValidationError(null)
      setServiceError(null)
      setPhase('loading')

      const started = Date.now()
      try {
        const result = await analyzeUrl(validation.url)
        // Keep the analyzing animation on screen long enough to read.
        const elapsed = Date.now() - started
        if (elapsed < MIN_LOADING_MS) await delay(MIN_LOADING_MS - elapsed)

        setCurrentResult(result)
        addHistoryEntry(result)
        navigate('/result')
      } catch (err) {
        const friendly =
          err instanceof AnalysisError ? err.message : FALLBACK_ERROR
        setServiceError({
          code: err && err.code ? err.code : 'malformed',
          message: friendly,
        })
        setPhase('error')
      }
    },
    [addHistoryEntry, navigate, setCurrentResult],
  )

  const handleSubmit = useCallback(
    (event) => {
      event.preventDefault()
      if (phase === 'loading') return // prevent duplicate submissions
      runScan(url)
    },
    [phase, runScan, url],
  )

  return (
    <div className="hero-glow">
      {/* Hero */}
      <section className="mx-auto max-w-6xl px-4 pb-12 pt-12 sm:px-6 sm:pt-16">
        <div className="mx-auto max-w-3xl text-center">
          <h1 className="animate-rise text-4xl font-extrabold leading-[1.08] tracking-tight text-ink sm:text-5xl lg:text-6xl">
            Check a link before{' '}
            <span className="bg-gradient-to-r from-brand to-blue-500 bg-clip-text text-transparent">
              you click.
            </span>
          </h1>
          <p className="animate-rise anim-delay-1 mx-auto mt-4 max-w-2xl text-base leading-relaxed text-muted sm:text-lg">
            Analyze a URL for suspicious patterns and known threats.
          </p>
        </div>

        {/* Scanner / loading / error */}
        <div className="mx-auto mt-8 max-w-3xl">
          {phase === 'loading' ? (
            <LoadingState url={url} />
          ) : (
            <div className="animate-rise anim-delay-2 space-y-4">
              {phase === 'error' && serviceError ? (
                <ErrorMessage
                  code={serviceError.code}
                  message={serviceError.message}
                  onRetry={() => runScan(url)}
                />
              ) : null}

              <UrlScanner
                url={url}
                onUrlChange={handleUrlChange}
                onSubmit={handleSubmit}
                onClear={handleClear}
                disabled={phase === 'loading'}
                error={validationError}
              />
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
