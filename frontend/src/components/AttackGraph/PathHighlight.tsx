import React from 'react'

interface Props { path: string[]; probability: number }

export function PathHighlight({ path, probability }: Props) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: '#8892a6' }}>
      {path.map((node, i) => (
        <React.Fragment key={node}>
          <span style={{ color: '#e0e6f0', fontWeight: 500 }}>{node.split('::')[0]}</span>
          {i < path.length - 1 && <span style={{ color: '#3a4560' }}>→</span>}
        </React.Fragment>
      ))}
      <span style={{ marginLeft: 8, color: '#ffa502', fontWeight: 600 }}>p={probability.toFixed(2)}</span>
    </div>
  )
}
