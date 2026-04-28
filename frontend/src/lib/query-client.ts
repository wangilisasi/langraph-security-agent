import { QueryClient } from '@tanstack/react-query'

/** Shared defaults for dashboard-style GET requests (same-origin FastAPI). */
export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60_000,
        gcTime: 5 * 60_000,
        retry: 1,
        refetchOnWindowFocus: true,
      },
    },
  })
}
