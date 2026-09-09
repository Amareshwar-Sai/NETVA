import React from 'react'
import { useSelector } from 'react-redux'
import type { RootState } from '../../main'

const s: Record<string, React.CSSProperties> = {
  list: { fontSize: 11 },
  item: { display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: '1px solid #1a2338' },
  rank: { color: '#5a6580', fontWeight: 600, width: 20 },
  name: { flex: 1, color: '#e0e6f0' },
  score: { fontWeight: 600, fontSize: 12 },
  empty: { color: '#3a4560', fontSize: 12, padding: 8 },
}

export function CriticalNodes() {
  const nodes = useSelector((st: RootState) => st.graph.nodes)
  if (!nodes || nodes.length === 0) return <div style={s.empty}>No nodes</div>

  const sorted = [...nodes]
    .filter((n: any) => n.state_id !== 'internet')
    .sort((a: any, b: any) => (b.centrality_composite || 0) - (a.centrality_composite || 0))
    .slice(0, 5)

  return (
    <div style={s.list}>
      {sorted.map((n: any, i: number) => (
        <div key={n.state_id} style={s.item}>
          <span style={s.rank}>{i + 1}</span>
          <span style={s.name}>{n.hostname || n.host_id} [{n.privilege}]</span>
          <span style={{ ...s.score, color: (n.risk_score || 0) >= 0.6 ? '#ff4757' : '#ffa502' }}>
            {((n.centrality_composite || 0) * 100).toFixed(0)}
          </span>
        </div>
      ))}
    </div>
  )
}
