import React from 'react'
import { useSelector } from 'react-redux'
import type { RootState } from '../../main'

const s: Record<string, React.CSSProperties> = {
  item: { padding: '8px 0', borderBottom: '1px solid #1a2338', fontSize: 11 },
  pathRow: { display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' },
  node: { color: '#e0e6f0', fontWeight: 500 },
  arrow: { color: '#3a4560', fontSize: 10 },
  prob: { marginLeft: 'auto', fontWeight: 600, fontSize: 12 },
  bar: { height: 3, borderRadius: 2, marginTop: 4, background: '#1a2338' },
  barFill: { height: 3, borderRadius: 2 },
  empty: { color: '#3a4560', fontSize: 12, padding: 8 },
}

function nodeLabel(stateId: string, hostnameMap: Record<string, string>): string {
  const ip = stateId.split('::')[0]
  const priv = stateId.split('::')[1] || ''
  const name = hostnameMap[ip] || hostnameMap[stateId] || ip
  return priv ? `${name} [${priv}]` : name
}

export function AttackPathList() {
  const paths = useSelector((s: RootState) => s.risk.criticalPaths)
  const graphNodes = useSelector((s: RootState) => s.graph.nodes)

  // Build IP → hostname lookup from graph nodes
  const hostnameMap: Record<string, string> = {}
  if (graphNodes) {
    graphNodes.forEach((n: any) => {
      if (n.hostname && n.ip) hostnameMap[n.ip] = n.hostname
      if (n.hostname && n.host_id) hostnameMap[n.host_id] = n.hostname
      if (n.hostname && n.state_id) hostnameMap[n.state_id] = n.hostname
    })
  }

  if (!paths || paths.length === 0) return <div style={s.empty}>No attack paths found</div>

  return (
    <div>
      {paths.map((p: any, i: number) => {
        const probColor = p.probability >= 0.7 ? '#ff4757' : p.probability >= 0.3 ? '#ffa502' : '#2ed573'
        return (
          <div key={i} style={s.item}>
            <div style={s.pathRow}>
              <span style={{ color: '#5a6580', marginRight: 6 }}>{i + 1}.</span>
              {p.path.map((node: string, j: number) => (
                <React.Fragment key={j}>
                  <span style={s.node}>{nodeLabel(node, hostnameMap)}</span>
                  {j < p.path.length - 1 && <span style={s.arrow}>→</span>}
                </React.Fragment>
              ))}
              <span style={{ ...s.prob, color: probColor }}>p={p.probability.toFixed(3)}</span>
            </div>
            <div style={s.bar}>
              <div style={{ ...s.barFill, width: `${p.probability * 100}%`, background: probColor }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}
