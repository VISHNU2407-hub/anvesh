import { useEffect } from 'react'
import {
  HashRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom'
import Footer from './components/Footer'
import Header from './components/Header'
import Home from './pages/Home'
import HowItWorks from './pages/HowItWorks'
import Result from './pages/Result'
import ScanHistory from './pages/ScanHistory'
import { ScanProvider } from './state/scanProvider'

/** Reset scroll position whenever the route changes. */
function ScrollToTop() {
  const { pathname } = useLocation()
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' })
  }, [pathname])
  return null
}

/** Short fade when switching pages — no loading overlay, no routing changes. */
function AnimatedRoutes() {
  const location = useLocation()
  return (
    <div key={location.pathname} className="animate-page-fade">
      <Routes location={location}>
        <Route path="/" element={<Home />} />
        <Route path="/result" element={<Result />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/how-it-works" element={<HowItWorks />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  )
}

/**
 * URLens application shell: header, routed pages, and footer.
 * HashRouter keeps navigation working on any static host without server
 * configuration.
 */
export default function App() {
  return (
    <ScanProvider>
      <HashRouter>
        <ScrollToTop />
        <div className="flex min-h-screen flex-col">
          <Header />
          <main id="main" className="flex-1">
            <AnimatedRoutes />
          </main>
          <Footer />
        </div>
      </HashRouter>
    </ScanProvider>
  )
}
