import { useIncidentsQuery, type IncidentRow } from '../api/dashboard-queries'
import { getQueryErrorMessage } from '../lib/query-error'

function incidentRowKey(row: IncidentRow, index: number): string {
  const id = row.request_id
  if (typeof id === 'string' && id.length > 0) return id
  if (typeof id === 'number' && Number.isFinite(id)) return String(id)
  return `row-${index}`
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export function AuditPage() {
  const { data, isPending, isError, error } = useIncidentsQuery(50)

  const rows: IncidentRow[] = data ?? []

  return (
    <div>
      <p className="eyebrow">Live data</p>
      <h1>Recent incidents</h1>
      <p className="tagline">
        Rows from <code>GET /incidents?limit=50</code>.
      </p>

      {isPending && <p className="panel muted">Loading…</p>}
      {isError && (
        <p className="panel error">Could not load incidents: {getQueryErrorMessage(error)}</p>
      )}
      {!isPending && !isError && rows.length === 0 && (
        <p className="panel muted">No incidents yet.</p>
      )}
      {!isPending && !isError && rows.length > 0 && (
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
              {rows.map((row, rowIndex) => (
                <tr key={incidentRowKey(row, rowIndex)}>
                  {Object.keys(rows[0]).map((key) => (
                    <td key={key}>{formatCell(row[key])}</td>
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
