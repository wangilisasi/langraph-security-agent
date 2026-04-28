export const queryKeys = {
  stats: ['stats'] as const,
  incidents: (limit: number) => ['incidents', limit] as const,
} as const
