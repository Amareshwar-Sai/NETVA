import React, { useState } from 'react'
import { executeAction, simulateAction } from '../../api/remediation'

const baseStyle: React.CSSProperties = {
  padding: '5px 10px', borderRadius: 4, fontSize: 10, fontWeight: 600,
  cursor: 'pointer', border: 'none', transition: 'opacity 0.2s',
}

interface Props {
  actionId: string
  targetAssetId: string
  dryRun: boolean
  label: string
}

export function ExecuteButton({ actionId, targetAssetId, dryRun, label }: Props) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const style: React.CSSProperties = dryRun
    ? { ...baseStyle, background: '#1e2a42', color: '#00d4ff' }
    : { ...baseStyle, background: '#ff4757', color: '#fff' }

  async function handleClick() {
    if (!dryRun && !confirm(`Execute "${label}" on ${targetAssetId}? This will run real SSH commands.`)) return

    setLoading(true)
    setResult(null)
    try {
      const data = dryRun
        ? await simulateAction(actionId, targetAssetId)
        : await executeAction(actionId, targetAssetId, false)

      const delta = data.risk_delta || data.simulation?.risk_delta || 0
      setResult(dryRun ? `Risk Δ: ${(delta * 100).toFixed(1)}%` : (data.success ? '✓ Done' : '✗ Failed'))
    } catch (e: any) {
      setResult('Error: ' + (e.message || 'Unknown'))
    }
    setLoading(false)
  }

  return (
    <div>
      <button style={{ ...style, opacity: loading ? 0.5 : 1 }} onClick={handleClick} disabled={loading}>
        {loading ? '...' : label}
      </button>
      {result && <div style={{ fontSize: 9, color: '#6b7a99', marginTop: 3 }}>{result}</div>}
    </div>
  )
}
