// Client d'API : lit TOUJOURS la reponse en texte avant de parser.
// Un reverse proxy peut renvoyer une page HTML (timeout, 502) : sans ce garde-fou
// le front afficherait « Unexpected token '<' » au lieu d'un message clair.

export type Step = { label: string; detail: string; status: 'ok' | 'running' | 'warn' | 'error'; ts: number }

export type Job<T = any> = {
  id: string
  kind: string
  label: string
  status: 'running' | 'done' | 'error'
  elapsed: number
  steps: Step[]
  result: T | null
  error: string | null
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...init })
  const text = await response.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    throw new Error(
      response.ok
        ? "Le serveur a renvoye une page inattendue (HTML au lieu de donnees)."
        : `Le serveur n'a pas repondu correctement (erreur ${response.status}).`,
    )
  }
  if (!response.ok) {
    const detail = data?.detail
    throw new Error(typeof detail === 'string' ? detail : `Erreur ${response.status}`)
  }
  return data as T
}

const post = <T>(url: string, body: unknown) => request<T>(url, { method: 'POST', body: JSON.stringify(body) })
const get = <T>(url: string) => request<T>(url)

export type Meta = {
  app: string
  version: string
  record_types: string[]
  resolvers: Record<string, string>
  blacklists: Record<string, string>
}

export type Criterion = { ok: boolean; detail: string }

export type Summary = {
  domain: string
  ip: string | null
  scanned_at: string
  lookup: Record<string, string[]>
  propagation: { total: number; success: number; consensus: string; consensus_pct: number; details: { name: string; ip: string; result: string; ok: boolean }[] }
  email: { score: number; max_score: number; criteria: Record<string, Criterion>; mx: { servers: string[] }; spf: { mechanism: string }; dkim: { present: boolean }; dmarc: { present: boolean; policy: string | null } }
  subdomains: { count: number; list: Record<string, string[]> }
  geo: { count: number; ips: { ip: string; geo: { city: string | null; country: string | null; isp: string | null }; subdomains: string[] }[] }
  blacklist: null | { ip: string; total: number; listed: number; warnings: number; errors: number; unknown: number; clean: number; details: { name: string; status: string; code: string | null; detail: string }[] }
  security: null | { score: number; max_score: number; criteria: Record<string, Criterion>; dnssec: any; caa: any; http_headers: any; tls: any }
  whois: null | { registrar: string | null; creation_date: string | null; expiration_date: string | null; name_servers: string[] }
  findings: { severity: 'critique' | 'moyen' | 'info'; title: string; detail: string }[]
}

export const api = {
  meta: () => get<Meta>('/api/meta'),
  health: () => get<{ status: string; version: string }>('/api/health'),

  summary: (domain: string) => post<{ job_id: string }>('/api/summary/run', { domain }),
  lookup: (domain: string, record_type: string, resolver: string) =>
    post<{ domain: string; type: string; records: string[]; count: number; resolver: string | null; error: string | null }>(
      '/api/dns/lookup', { domain, record_type, resolver }),
  email: (domain: string, selector: string) => post<any>('/api/email/check', { domain, selector }),
  whois: (domain: string) => post<any>('/api/whois/lookup', { domain }),
  geo: (target: string) => post<any>('/api/geo/locate', { target }),

  blacklist: (target: string) => post<{ job_id: string }>('/api/blacklist/run', { target }),
  propagation: (domain: string, record_type: string) => post<{ job_id: string }>('/api/propagation/run', { domain, record_type }),
  subdomains: (domain: string, bruteforce: boolean, crtsh: boolean) =>
    post<{ job_id: string }>('/api/subdomains/run', { domain, bruteforce, crtsh }),
  security: (domain: string, subdomains: string[]) => post<{ job_id: string }>('/api/security/run', { domain, subdomains }),
  report: (domain: string, ip: string) => post<{ job_id: string }>('/api/report/run', { domain, ip }),

  job: <T,>(id: string) => get<Job<T>>(`/api/jobs/${id}`),
}
