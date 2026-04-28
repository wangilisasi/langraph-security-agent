import { useEffect, useState } from 'react'

type IncidentRow = Record<string, unknown>

export function AuditPage() {
  const [rows, setRows] = useState<IncidentRow[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetch('/incidents?limit=50')
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
        return res.json()
      })
      .then((json: unknown) => {
        if (!cancelled) setRows(Array.isArray(json) ? (json as IncidentRow[]) : [])
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
      <h1>Recent incidents</h1>
      <p className="tagline">Rows from <code>GET /incidents?limit=50</code>.</p>

      {loading && <p className="panel muted">Loading…</p>}
      {error && <p className="panel error">Could not load incidents: {error}</p>}
      {!loading && !error && rows && rows.length === 0 && (
        <p className="panel muted">No incidents yet.</p>
      )}
      {!loading && !error && rows && rows.length > 0 && (
        <div className="table-wrap" role="region" aria-label="Incidents table">
          <table className="incident-table">
            <thead>
              <tr>
                {Object.keys(rows[0]).map((key) => (
                  <th key={key}>{key}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i}>
                  {Object.keys(rows[0]).map((key) => (
                    <td key={key}>
                      {formatCell(row[key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
