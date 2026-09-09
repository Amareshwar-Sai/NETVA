import React from 'react'
import { useSelector } from 'react-redux'
import type { RootState } from '../../main'

const stages = ['ingestion', 'normalization', 'assets', 'graph_building', 'graph_complete', 'amc_solving', 'amc_complete', 'mdp_training', 'done']
const stageLabels: Record<string, string> = {
  ingestion: 'Ingestion', normalization: 'Normalization', assets: 'Assets Found',
  graph_building: 'Building Graph', graph_complete: 'Graph Complete',
  amc_solving: 'AMC Engine', amc_complete: 'AMC Complete',
  mdp_training: 'Q-Learning', done: 'Complete',
}

const s: Record<string, React.CSSProperties> = {
  container: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 },
  stage: { display: 'flex', alignItems: 'center', gap: 4 },
  icon: { width: 14, height: 14, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 700 },
  barTrack: { flex: 1, height: 4, borderRadius: 2, background: '#1a2338' },
  barFill: { height: 4, borderRadius: 2, background: 'linear-gradient(90deg, #7b61ff, #00d4ff)', transition: 'width 0.3s ease' },
  message: { color: '#8892a6', fontSize: 10 },
}

export function ScanProgress() {
  const scan = useSelector((st: RootState) => st.scan)
  const currentIdx = stages.indexOf(scan.stage)

  return (
    <div>
      <div style={s.container}>
        {stages.map((stage, i) => {
          const done = i <= currentIdx
          const active = stage === scan.stage
          return (
            <div key={stage} style={s.stage}>
              <div style={{
                ...s.icon,
                background: done ? '#2ed573' : active ? '#ffa502' : '#1e2a42',
                color: done ? '#0a0e17' : '#5a6580',
              }}>
                {done ? '✓' : active ? '⟳' : ''}
              </div>
              <span style={{ color: done ? '#e0e6f0' : '#5a6580' }}>
                {stageLabels[stage] || stage}
              </span>
            </div>
          )
        })}
      </div>
      <div style={{ marginTop: 4 }}>
        <div style={s.barTrack}>
          <div style={{ ...s.barFill, width: `${scan.progress}%` }} />
        </div>
        <div style={s.message}>{scan.message}</div>
      </div>
    </div>
  )
}
