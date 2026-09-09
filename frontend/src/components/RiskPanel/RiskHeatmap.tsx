import React from 'react'
import { useSelector } from 'react-redux'
import type { RootState } from '../../main'

const s: Record<string, React.CSSProperties> = {
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 8 },
  cell: { padding: 10, borderRadius: 6, border: '1px solid #1e2a42', fontSize: 11, position: 'relative' },
  name: { fontWeight: 600, fontSize: 12, marginBottom: 4 },
  metric: { display: 'flex', justifyContent: 'space-between', padding: '2px 0' },
  empty: { color: '#3a4560', fontSize: 12, padding: 16 },
}

function riskColor(score: number): string {
  if (score >= 0.8) return '#ff4757'
  if (score >= 0.6) return '#ff6348'
  if (score >= 0.4) return '#ffa502'
  if (score >= 0.2) return '#2ed573'
  return '#20bf6b'
}

export function RiskHeatmap() {
  const metrics = useSelector((s: RootState) => s.risk.stateMetrics)
  if (!metrics || metrics.length === 0) return <div style={s.empty}>No risk data yet</div>

  return (
    <div style={s.grid}>
      {metrics.map((m: any) => (
        <div key={m.state_id} style={{ ...s.cell, borderColor: riskColor(m.risk_score), background: `${riskColor(m.risk_score)}10` }}>
          <div style={{ ...s.name, color: riskColor(m.risk_score) }}>
            {m.hostname || m.state_id.split('::')[0]}
          </div>
          <div style={{ fontSize: 9, color: '#5a6580', marginBottom: 4 }}>{m.state_id.split('::')[1] || m.state_id}</div>
          <div style={s.metric}>
            <span style={{ color: '#6b7a99' }}>Risk</span>
            <span style={{ color: riskColor(m.risk_score), fontWeight: 600 }}>{(m.risk_score * 100).toFixed(0)}%</span>
          </div>
          <div style={s.metric}>
            <span style={{ color: '#6b7a99' }}>Absorb</span>
            <span>{(m.absorption_prob * 100).toFixed(0)}%</span>
          </div>
          <div style={s.metric}>
            <span style={{ color: '#6b7a99' }}>Steps</span>
            <span>{m.expected_steps.toFixed(1)}</span>
          </div>
        </div>
      ))}
    </div>
  )
}
