import { useEffect, useState } from 'react'

export function MonitoringPage() {
  const [data, setData] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetch('/stats')
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
        return res.json()
      })
      .then((json) => {
        if (!cancelled) setData(json)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Request failed')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div>
      <p className="eyebrow">Live data</p>
      <h1>Detection stats</h1>
      <p className="tagline">Same JSON as <code>GET /stats</code>, formatted for reading.</p>

      {loading && <p className="panel muted">Loading…</p>}
      {error && <p className="panel error">Could not load stats: {error}</p>}
      {!loading && !error && (
        <pre className="json-panel" role="region" aria-label="Stats JSON">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  )
}
