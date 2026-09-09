import React, { useState } from 'react'
import { useDispatch } from 'react-redux'
import { simulateAction } from '../../api/remediation'
import { setGraph } from '../../store/graphSlice'
import { BeforeAfterDiff } from './BeforeAfterDiff'

const s: Record<string, React.CSSProperties> = {
  card: {
    minWidth: 240, padding: 12, background: '#111827', border: '1px solid #1e2a42',
    borderRadius: 8, fontSize: 11, flexShrink: 0,
  },
  stepBadge: {
    display: 'inline-block', padding: '2px 8px', borderRadius: 4,
    background: '#1e2a42', fontWeight: 700, fontSize: 10, marginBottom: 6,
  },
  label: { fontWeight: 600, fontSize: 13, color: '#e0e6f0', marginBottom: 4 },
  target: { color: '#6b7a99', marginBottom: 8, fontSize: 10 },
  pills: { display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' as const },
  pill: { padding: '2px 6px', borderRadius: 3, fontSize: 9, fontWeight: 500 },
  delta: { fontSize: 14, fontWeight: 700, marginBottom: 8 },
  desc: { color: '#5a6580', fontSize: 10, lineHeight: 1.4, marginBottom: 8 },
  simBtn: {
    width: '100%', padding: '6px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600,
    cursor: 'pointer', border: '1px solid #1e3a5f', background: '#0d1828',
    color: '#00d4ff',
  },
  simBtnApplied: {
    width: '100%', padding: '6px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600,
    cursor: 'pointer', border: '1px solid #2ed573', background: '#0d2218',
    color: '#2ed573',
  },
  simBtnLoading: {
    width: '100%', padding: '6px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600,
    border: '1px solid #1e3a5f', background: '#0d1828',
    color: '#5a6580', cursor: 'wait', opacity: 0.7,
  },
  diffWrap: { marginTop: 8 },
  errMsg: { fontSize: 10, color: '#ff4757', marginTop: 4 },
}

interface Props { step: any }

export function ActionCard({ step }: Props) {
  const dispatch = useDispatch()
  const [simulating, setSimulating] = useState(false)
  const [simResult, setSimResult] = useState<any>(null)
  const [applied, setApplied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const typeColor: Record<string, string> = {
    patch: '#2ed573', isolate: '#ff4757', block_port: '#ffa502',
    harden: '#00d4ff', revoke: '#7b61ff', segment: '#ff6348', monitor: '#20bf6b',
  }
  const color = typeColor[step.action_type] || '#8892a6'

  async function handleSimulate() {
    setSimulating(true)
    setError(null)
    try {
      const result = await simulateAction(step.action_id, step.target_asset_id)
      setSimResult(result)

      // 1. Update graph topology
      if (result.graph_after && result.graph_after.nodes) {
        dispatch(setGraph({
          nodes: result.graph_after.nodes,
          edges: result.graph_after.edges,
        }))
      }

      // 2. Update risk slice: state_metrics, paths, summary
      if (result.state_metrics_after || result.paths_after || result.summary_after) {
        dispatch({
          type: 'risk/applySimulation',
          payload: {
            stateMetrics: result.state_metrics_after || [],
            criticalPaths: result.paths_after || [],
            summary: result.summary_after || null,
          },
        })
      }

      setApplied(true)
    } catch (e: any) {
      setError(e.message || 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  let btnStyle = s.simBtn
  let btnLabel = 'Simulate Apply'
  if (simulating) {
    btnStyle = s.simBtnLoading
    btnLabel = 'Simulating…'
  } else if (applied) {
    btnStyle = s.simBtnApplied
    btnLabel = '✓ Applied (preview)'
  }

  return (
    <div style={s.card}>
      <div style={{ ...s.stepBadge, color }}>Step {step.step}</div>
      <div style={s.label}>{step.action_label}</div>
      <div style={s.target}>{step.target_hostname || step.target_asset_id}</div>

      <div style={s.pills}>
        <span style={{ ...s.pill, background: `${color}20`, color }}>
          {step.action_type}
        </span>
        <span style={{ ...s.pill, background: '#ffa50220', color: '#ffa502' }}>
          cost: {step.cost.toFixed(2)}
        </span>
        <span style={{ ...s.pill, background: '#ff475720', color: '#ff4757' }}>
          disrupt: {step.disruption.toFixed(2)}
        </span>
      </div>

      <div style={{ ...s.delta, color: '#2ed573' }}>
        −{(step.risk_delta * 100).toFixed(1)}% risk
      </div>

      <div style={s.desc}>{step.description}</div>

      <button
        style={btnStyle}
        onClick={handleSimulate}
        disabled={simulating}
      >
        {btnLabel}
      </button>

      {error && <div style={s.errMsg}>{error}</div>}

      {simResult && (
        <div style={s.diffWrap}>
          <BeforeAfterDiff data={simResult} />
        </div>
      )}
    </div>
  )
}