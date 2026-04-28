export function getQueryErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  return 'Request failed'
}
