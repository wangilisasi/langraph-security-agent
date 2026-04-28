import { useStatsQuery } from '../api/dashboard-queries'
import { getQueryErrorMessage } from '../lib/query-error'

export function MonitoringPage() {
  const { data, isPending, isError, error } = useStatsQuery()

  return (
    <div>
      <p className="eyebrow">Live data</p>
      <h1>Detection stats</h1>
      <p className="tagline">
        Same JSON as <code>GET /stats</code>, formatted for reading.
      </p>

      {isPending && <p className="panel muted">Loading…</p>}
      {isError && (
        <p className="panel error">Could not load stats: {getQueryErrorMessage(error)}</p>
      )}
      {!isPending && !isError && (
        <pre className="json-panel" role="region" aria-label="Stats JSON">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  )
}
