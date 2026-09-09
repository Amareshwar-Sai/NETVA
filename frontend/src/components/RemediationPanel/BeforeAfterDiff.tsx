import React from 'react'

const s: Record<string, React.CSSProperties> = {
  container: {
    background: '#0d1320', border: '1px solid #1e2a42', borderRadius: 6,
    padding: 8, fontSize: 10, marginTop: 4,
  },
  row: { display: 'flex', justifyContent: 'space-between', padding: '2px 0' },
  label: { color: '#6b7a99', fontSize: 9 },
  before: { color: '#ff4757', fontWeight: 600 },
  after: { color: '#2ed573', fontWeight: 600 },
  arrow: { color: '#5a6580', margin: '0 4px' },
  removedTitle: { color: '#5a6580', fontSize: 9, marginTop: 4 },
  removedList: { color: '#7b61ff', fontSize: 9, lineHeight: 1.4 },
}

interface Props { data: any }

export function BeforeAfterDiff({ data }: Props) {
  if (!data) return null

  const removed = data.removed_edges || []

  return (
    <div style={s.container}>
      <div style={s.row}>
        <span style={s.label}>Risk</span>
        <span>
          <span style={s.before}>{(data.risk_before * 100).toFixed(1)}%</span>
          <span style={s.arrow}>→</span>
          <span style={s.after}>{(data.risk_after * 100).toFixed(1)}%</span>
        </span>
      </div>
      <div style={s.row}>
        <span style={s.label}>Edges</span>
        <span>
          <span style={s.before}>{data.edges_before}</span>
          <span style={s.arrow}>→</span>
          <span style={s.after}>{data.edges_after}</span>
        </span>
      </div>
      {removed.length > 0 && (
        <>
          <div style={s.removedTitle}>{removed.length} edge(s) removed:</div>
          <div style={s.removedList}>
            {removed.slice(0, 3).map((e: any, i: number) => (
              <div key={i}>• {e.reason || `${e.from} → ${e.to}`}</div>
            ))}
            {removed.length > 3 && <div>• …and {removed.length - 3} more</div>}
          </div>
        </>
      )}
    </div>
  )
}