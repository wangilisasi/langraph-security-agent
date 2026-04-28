import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './Layout'
import { AuditPage } from './pages/AuditPage'
import { HomePage } from './pages/HomePage'
import { MonitoringPage } from './pages/MonitoringPage'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/monitoring" element={<MonitoringPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
