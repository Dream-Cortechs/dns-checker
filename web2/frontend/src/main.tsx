import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './styles/theme-cortechs.css'
import './styles/app.css'

// Anti-flash : le theme memorise est applique AVANT le premier rendu.
try {
  const t = localStorage.getItem('erp-theme')
  if (t) document.documentElement.setAttribute('data-theme', t)
} catch { /* ignore */ }

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
