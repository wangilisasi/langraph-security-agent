import { useQuery } from '@tanstack/react-query'

import { fetchJson } from './http'
import { queryKeys } from './query-keys'

export type IncidentRow = Record<string, unknown>

export function useStatsQuery() {
  return useQuery({
    queryKey: queryKeys.stats,
    queryFn: () => fetchJson<unknown>('/stats'),
  })
}

export function useIncidentsQuery(limit = 50) {
  return useQuery({
    queryKey: queryKeys.incidents(limit),
    queryFn: async () => {
      const json = await fetchJson<unknown>(`/incidents?limit=${limit}`)
      return Array.isArray(json) ? (json as IncidentRow[]) : []
    },
  })
}
