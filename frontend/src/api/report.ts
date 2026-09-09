/**
 * Report API — trigger PDF download from /report/pdf
 */
import { API_BASE } from './client'

export async function downloadReport(): Promise<void> {
  const res = await fetch(`${API_BASE}/report/pdf`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to generate report')
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'NETVA_Report.pdf'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
