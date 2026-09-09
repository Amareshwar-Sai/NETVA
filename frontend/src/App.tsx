import React, { useEffect, useState } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import type { RootState, AppDispatch } from './main'
import { fetchGraph } from './store/graphSlice'
import { fetchRisk } from './store/riskSlice'
import { fetchRemediation } from './store/remediationSlice'
import { updateScanProgress } from './store/scanSlice'
import { downloadReport } from './api/report'
import { AttackGraph } from './components/AttackGraph/AttackGraph'
import { RiskHeatmap } from './components/RiskPanel/RiskHeatmap'
import { AttackPathList } from './components/RiskPanel/AttackPathList'
import { CriticalNodes } from './components/RiskPanel/CriticalNodes'
import { ActionQueue } from './components/RemediationPanel/ActionQueue'
import { ScanUpload } from './components/ScanPanel/ScanUpload'
import { ScanProgress } from './components/ScanPanel/ScanProgress'
import { connectWebSocket } from './api/ws'

const styles: Record<string, React.CSSProperties> = {
  app: {
    fontFamily: "'JetBrains Mono', 'Inter', monospace",
    background: '#0a0e17',
    color: '#e0e6f0',
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    background: 'linear-gradient(135deg, #0d1320 0%, #131b2e 100%)',
    borderBottom: '1px solid #1e2a42',
    padding: '12px 24px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 16,
  },
  logo: {
    fontSize: 20,
    fontWeight: 700,
    background: 'linear-gradient(135deg, #00d4ff, #7b61ff)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    letterSpacing: 2,
  },
  headerStats: {
    display: 'flex',
    gap: 20,
    fontSize: 12,
    color: '#8892a6',
  },
  statBadge: {
    padding: '4px 10px',
    borderRadius: 4,
    background: '#141c2f',
    border: '1px solid #1e2a42',
  },
  main: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gridTemplateRows: '1fr auto',
    flex: 1,
    gap: 1,
    background: '#1e2a42',
  },
  panel: {
    background: '#0d1320',
    padding: 16,
    overflow: 'auto',
  },
  bottomPanel: {
    gridColumn: '1 / -1',
    background: '#0d1320',
    padding: 16,
    borderTop: '1px solid #1e2a42',
    maxHeight: 350,
    overflow: 'auto',
  },
  sectionTitle: {
    fontSize: 11,
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: 1.5,
    color: '#5a6580',
    marginBottom: 12,
  },
  reportBtn: {
    padding: '6px 14px',
    borderRadius: 4,
    background: 'linear-gradient(135deg, #00b4d8, #7b61ff)',
    color: '#fff',
    border: 'none',
    cursor: 'pointer',
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 0.5,
    display: 'flex',
    alignItems: 'center',
    gap: 6,
  },
  reportBtnDisabled: {
    padding: '6px 14px',
    borderRadius: 4,
    background: '#1e2a42',
    color: '#5a6580',
    border: '1px solid #2a3654',
    cursor: 'not-allowed',
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 0.5,
  },
}

function App() {
  const dispatch = useDispatch<AppDispatch>()
  const scan = useSelector((s: RootState) => s.scan)
  const graph = useSelector((s: RootState) => s.graph)
  const risk = useSelector((s: RootState) => s.risk)
  const [reportLoading, setReportLoading] = useState(false)

  const handleDownloadReport = async () => {
    setReportLoading(true)
    try {
      await downloadReport()
    } catch (err: any) {
      alert(err.message || 'Report generation failed')
    } finally {
      setReportLoading(false)
    }
  }

  useEffect(() => {
    const cleanup = connectWebSocket((msg: any) => {
      if (msg.type === 'progress') {
        dispatch(updateScanProgress({
          stage: msg.stage,
          progress: msg.progress,
          message: msg.message,
          status: 'running',
        }))
      } else if (msg.type === 'complete') {
        dispatch(updateScanProgress({ status: 'complete', progress: 100, stage: 'done', message: msg.message }))
        dispatch(fetchGraph() as any)
        dispatch(fetchRisk() as any)
        dispatch(fetchRemediation() as any)
      } else if (msg.type === 'graph_update') {
        dispatch(fetchGraph() as any)
      } else if (msg.type === 'error') {
        dispatch(updateScanProgress({ status: 'error', message: msg.error }))
      }
    })
    return cleanup
  }, [dispatch])

  const riskLevel = risk.summary?.max_risk_score
    ? risk.summary.max_risk_score >= 0.7 ? 'CRITICAL' : risk.summary.max_risk_score >= 0.4 ? 'HIGH' : 'LOW'
    : '—'
  const riskColor = riskLevel === 'CRITICAL' ? '#ff4757' : riskLevel === 'HIGH' ? '#ffa502' : '#2ed573'

  return (
    <div style={styles.app}>
      {/* Header */}
      <header style={styles.header}>
        <span style={styles.logo}>◆ NETVA</span>
        <div style={styles.headerStats}>
          <ScanUpload />
          {scan.status === 'complete' ? (
            <button
              style={reportLoading ? styles.reportBtnDisabled : styles.reportBtn}
              onClick={handleDownloadReport}
              disabled={reportLoading}
            >
              {reportLoading ? '⏳ Generating...' : '📄 Download Report'}
            </button>
          ) : (
            <button style={styles.reportBtnDisabled} disabled>
              📄 Download Report
            </button>
          )}
          <span style={{ ...styles.statBadge, borderColor: riskColor, color: riskColor }}>
            Risk: {riskLevel}
          </span>
          <span style={styles.statBadge}>
            Assets: {risk.summary?.total_assets ?? '—'}
          </span>
          <span style={styles.statBadge}>
            Vulns: {risk.summary?.total_vulns ?? '—'}
          </span>
          <span style={styles.statBadge}>
            Paths: {risk.summary?.attack_paths ?? '—'}
          </span>
        </div>
      </header>

      {/* Show progress if scanning */}
      {scan.status === 'running' && (
        <div style={{ padding: '8px 24px', background: '#111827' }}>
          <ScanProgress />
        </div>
      )}

      {/* Main 4-panel layout */}
      <div style={styles.main}>
        {/* Attack Graph (left) */}
        <div style={styles.panel}>
          <div style={styles.sectionTitle}>Attack Graph</div>
          <AttackGraph />
        </div>

        {/* Risk Panel (right) */}
        <div style={styles.panel}>
          <div style={styles.sectionTitle}>Risk Analysis</div>
          <RiskHeatmap />
          <div style={{ ...styles.sectionTitle, marginTop: 16 }}>Attack Paths</div>
          <AttackPathList />
          <div style={{ ...styles.sectionTitle, marginTop: 16 }}>Critical Nodes</div>
          <CriticalNodes />
        </div>

        {/* Remediation Panel (bottom) */}
        <div style={styles.bottomPanel}>
          <div style={styles.sectionTitle}>Remediation — Optimal Defense Sequence</div>
          <ActionQueue />
        </div>
      </div>
    </div>
  )
}

export default App
