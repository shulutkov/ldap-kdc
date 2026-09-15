// The management API as the console sees it.
//
// Signing in is two ways of getting ONE thing: a short-lived session token, from a Kerberos ticket
// through SPNEGO or from a login and a password. The token is kept for the tab's lifetime and
// presented as a bearer, and the server re-checks on every request that its holder still
// administers the directory — so what this page can do is always what the server allows, never
// what the page remembers.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

export type Session = { token: string; subject: string; method: 'password' | 'kerberos'; expiresAt: string }
export type WhoAmI = { subject: string; method: string; expiresAt?: string }

export type Capability = { action: string; object: string }
export type Item = Record<string, unknown>

export type Stats = {
  realm: string
  users: { total: number; disabled: number; withoutPassword: number }
  groups: number
  principals: number
  trusts: number
  encTypes: string[]
}

export const TOKEN = 'ldap-kdc.token'
// SIGNED_OUT marks a tab whose person pressed Sign out. Kerberos sign-in happens by itself, so
// without the marker the console would sign them straight back in with the ticket they still hold.
export const SIGNED_OUT = 'ldap-kdc.signed-out'

async function errorOf(resp: Response): Promise<ApiError> {
  const text = await resp.text()
  let msg = resp.statusText
  try {
    msg = (JSON.parse(text) as { error?: string }).error ?? msg
  } catch {
    /* not JSON: the SPNEGO refusal is plain text */
  }
  return new ApiError(resp.status, msg)
}

// api performs one call and turns the API's {error} into an Error.
export async function api<T>(path: string, token: string | null, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', 'Bearer ' + token)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const resp = await fetch(path, { ...init, headers })
  if (!resp.ok) throw await errorOf(resp)
  const text = await resp.text()
  return (text ? JSON.parse(text) : undefined) as T
}

// signInWithKerberos asks the service to negotiate. A browser configured to trust this host answers
// the challenge itself with the ticket it already holds, so the person types nothing. One that is
// not configured gets the refusal back, and the page offers the password form instead.
export async function signInWithKerberos(): Promise<Session> {
  const resp = await fetch('/api/v1/auth/negotiate', { credentials: 'include' })
  if (!resp.ok) throw await errorOf(resp)
  return (await resp.json()) as Session
}

export async function signInWithPassword(login: string, password: string): Promise<Session> {
  return api<Session>('/api/v1/auth/login', null, { method: 'POST', body: JSON.stringify({ login, password }) })
}

// enc escapes a name for a path while keeping its slashes: a service principal's name contains them,
// and the API reads them as part of the name.
export const enc = (name: string) => name.split('/').map(encodeURIComponent).join('/')

// downloadKeytab fetches a keytab with the session and hands it to the browser as a file. A plain
// link cannot do it: the request has to carry the bearer.
export async function downloadKeytab(name: string, token: string): Promise<void> {
  const resp = await fetch(`/api/v1/principals/${enc(name)}/keytab`, { headers: { Authorization: 'Bearer ' + token } })
  if (!resp.ok) throw await errorOf(resp)
  const url = URL.createObjectURL(await resp.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = name.replace(/[/@]/g, '_') + '.keytab'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// describe turns a failure into a sentence an administrator can act on.
export function describe(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.status) {
      case 401:
        return 'The session has ended; sign in again.'
      case 403:
        return 'Not permitted: ' + e.message
      default:
        return `${e.status}: ${e.message}`
    }
  }
  return String(e)
}

// ---- the API's own description ---------------------------------------------------------------------

export type JSONSchema = Record<string, unknown>

type Operation = { requestBody?: { content?: Record<string, { schema?: JSONSchema }> } }

export type OpenAPI = {
  paths: Record<string, Record<string, Operation>>
  components: { schemas: Record<string, JSONSchema> }
}

let specCache: { token: string; spec: Promise<OpenAPI> } | null = null

// loadSpec fetches the OpenAPI document once per session. The console builds every form from it, so a
// form always describes the API it talks to, whatever version of the service is answering.
export function loadSpec(token: string): Promise<OpenAPI> {
  if (!specCache || specCache.token !== token) {
    const spec = api<OpenAPI>('/api/v1/openapi.json', token)
    specCache = { token, spec }
    spec.catch(() => {
      specCache = null
    })
  }
  return specCache.spec
}

// requestSchema is the body one operation accepts, as a schema a form can render on its own: the
// operation's schema with the document's components beside it, so the references inside it resolve.
export function requestSchema(spec: OpenAPI, method: 'post' | 'patch', path: string): JSONSchema | null {
  const body = spec.paths[path]?.[method]?.requestBody?.content?.['application/json']?.schema
  if (!body) return null
  const ref = typeof body.$ref === 'string' ? body.$ref : null
  const own = ref ? spec.components.schemas[ref.replace('#/components/schemas/', '')] : body
  if (!own) return null
  return { ...own, components: spec.components }
}
