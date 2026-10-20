import { Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import DnsLookup from './pages/DnsLookup'
import Propagation from './pages/Propagation'
import Email from './pages/Email'
import Blacklist from './pages/Blacklist'
import Whois from './pages/Whois'
import GeoIp from './pages/GeoIp'
import Subdomains from './pages/Subdomains'
import Security from './pages/Security'
import Report from './pages/Report'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/dns" element={<DnsLookup />} />
        <Route path="/propagation" element={<Propagation />} />
        <Route path="/email" element={<Email />} />
        <Route path="/blacklists" element={<Blacklist />} />
        <Route path="/whois" element={<Whois />} />
        <Route path="/geo" element={<GeoIp />} />
        <Route path="/sous-domaines" element={<Subdomains />} />
        <Route path="/securite" element={<Security />} />
        <Route path="/rapport" element={<Report />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  )
}
