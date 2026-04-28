/**
 * Same-origin JSON fetch helpers for the FastAPI backend.
 */

export class ApiError extends Error {
  readonly status: number

  readonly statusText: string

  constructor(status: number, statusText: string, message?: string) {
    super(message ?? `${status} ${statusText}`)
    this.name = 'ApiError'
    this.status = status
    this.statusText = statusText
  }
}

export async function fetchJson<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(input, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  })

  if (!res.ok) {
    throw new ApiError(res.status, res.statusText)
  }

  return res.json() as Promise<T>
}
