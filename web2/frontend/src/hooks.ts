import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { api, Job } from './api'

// -- Domaine courant, partage par tous les ecrans (memorise) -----------------
export const DomainContext = createContext<{ domain: string; setDomain: (d: string) => void }>({
  domain: 'cortechs.fr',
  setDomain: () => {},
})

export function useDomain() {
  return useContext(DomainContext)
}

export function useStoredDomain() {
  const [domain, setDomainState] = useState<string>(() => localStorage.getItem('dns-domain') || 'cortechs.fr')
  const setDomain = useCallback((value: string) => {
    setDomainState(value)
    try { localStorage.setItem('dns-domain', value) } catch { /* stockage indisponible */ }
  }, [])
  return { domain, setDomain }
}

// -- Theme sombre / clair (sombre par defaut) -------------------------------
export function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    (localStorage.getItem('erp-theme') as 'dark' | 'light') || 'dark')
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('erp-theme', theme) } catch { /* ignore */ }
  }, [theme])
  return { theme, toggle: () => setTheme(t => (t === 'dark' ? 'light' : 'dark')) }
}

// -- Tache de fond : lancement + suivi par interrogation periodique ---------
// La fonction de lancement est passe en argument (jamais recreee ici), sinon la
// boucle de suivi repartirait a chaque rendu.
export function useJob<T = any>() {
  const [job, setJob] = useState<Job<T> | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const cancel = useRef(false)

  useEffect(() => () => { cancel.current = true }, [])

  const reset = useCallback(() => { setJob(null); setError(null); setRunning(false); cancel.current = true }, [])

  const start = useCallback(async (launcher: () => Promise<{ job_id: string }>) => {
    cancel.current = false
    setRunning(true)
    setError(null)
    setJob(null)
    try {
      const { job_id } = await launcher()
      for (;;) {
        await new Promise(r => setTimeout(r, 700))
        if (cancel.current) return
        const state = await api.job<T>(job_id)
        setJob(state)
        if (state.status !== 'running') break
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      if (!cancel.current) setRunning(false)
    }
  }, [])

  return { job, running, error, start, reset }
}

// -- Appel direct (routes rapides) -----------------------------------------
export function useAsync<T>() {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = useCallback(async (fn: () => Promise<T>) => {
    setLoading(true); setError(null)
    try { setData(await fn()) }
    catch (exc) { setError(exc instanceof Error ? exc.message : String(exc)); setData(null) }
    finally { setLoading(false) }
  }, [])
  const reset = useCallback(() => { setData(null); setError(null) }, [])
  return { data, loading, error, run, reset }
}
