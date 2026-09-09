import React from 'react'

const s: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'absolute', top: 8, right: 8, width: 320,
    maxHeight: 'calc(100% - 16px)', overflowY: 'auto',
    background: '#111827', border: '1px solid #1e3a5f',
    borderRadius: 8, padding: 14, fontSize: 11, zIndex: 10,
  },
  close: {
    position: 'absolute', top: 6, right: 10, cursor: 'pointer',
    color: '#5a6580', fontSize: 16, background: 'none', border: 'none',
  },
  title: { fontWeight: 700, fontSize: 13, color: '#e0e6f0', marginBottom: 8 },
  row: {
    display: 'flex', justifyContent: 'space-between',
    padding: '3px 0', borderBottom: '1px solid #1a2338',
  },
  label: { color: '#6b7a99' },
  val: { color: '#e0e6f0', fontWeight: 500 },
  riskBig: { fontSize: 22, fontWeight: 700, margin: '6px 0' },
  cveSection: { marginTop: 10 },
  cveHeader: {
    fontSize: 11, fontWeight: 600, color: '#e0e6f0',
    marginBottom: 6, paddingBottom: 4, borderBottom: '1px solid #1e3a5f',
  },
  cveItem: {
    display: 'flex', justifyContent: 'space-between',
    alignItems: 'center', padding: '4px 0', fontSize: 10,
    borderBottom: '1px solid #1a2338',
  },
  cveId: {
    color: '#e0e6f0', fontFamily: 'monospace', fontSize: 10,
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
    flex: 1, marginRight: 8,
  },
  cveCvss: {
    fontWeight: 700, fontSize: 10, padding: '2px 6px',
    borderRadius: 3, minWidth: 32, textAlign: 'center',
  },
  cveExploit: {
    fontSize: 9, marginLeft: 6, color: '#ff4757',
  },
  flagSection: { marginTop: 8, fontSize: 10 },
  flagItem: {
    display: 'inline-block', padding: '2px 6px', margin: '2px 4px 2px 0',
    background: '#2a1a30', color: '#ff7a90', borderRadius: 3, fontSize: 9,
  },
  termReason: {
    marginTop: 8, padding: 6, background: '#1a1a30',
    borderLeft: '3px solid #ff4757', fontSize: 10, color: '#cbd5e0',
    borderRadius: 3,
  },
  empty: { color: '#5a6580', fontStyle: 'italic', fontSize: 10, padding: '4px 0' },
}

function cvssColor(cvss: number): { bg: string; fg: string } {
  if (cvss >= 9.0) return { bg: '#3a0a14', fg: '#ff4757' }
  if (cvss >= 7.0) return { bg: '#3a200a', fg: '#ffa502' }
  if (cvss >= 4.0) return { bg: '#2a2a0a', fg: '#ffd700' }
  return { bg: '#1a1a30', fg: '#7a8aab' }
}

interface Vuln {
  vuln_id: string
  name: string
  severity: string
  cvss: number
  exploit_available: boolean
  port: number
}

interface Asset {
  ip: string
  hostname: string
  vulns: Vuln[]
  flags: Record<string, boolean>
}

interface Props {
  node: any
  asset?: Asset | null  // optional — passed from parent if available
  onClose: () => void
}

export function NodeTooltip({ node, asset, onClose }: Props) {
  const riskColor =
    (node.risk_score || 0) >= 0.7 ? '#ff4757'
    : (node.risk_score || 0) >= 0.4 ? '#ffa502'
    : '#2ed573'

  // Synthetic nodes: external, perimeter_waf, internal_firewall_acl
  const isSynthetic = node.node_role === 'entry' || node.node_role === 'defense'

  // Top 5 CVEs sorted by CVSS desc
  const topVulns = (asset?.vulns || [])
    .filter(v => v.vuln_id || v.name)
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 5)

  // Active flags (truthy values from asset.flags)
  const activeFlags = asset?.flags
    ? Object.entries(asset.flags).filter(([_, v]) => v === true).map(([k]) => k)
    : []

  return (
    <div style={s.overlay}>
      <button style={s.close} onClick={onClose}>&times;</button>

      <div style={s.title}>{node.label || node.hostname || node.host_id}</div>

      {/* Synthetic node — show description, not host stats */}
      {isSynthetic && node.description && (
        <div style={{ ...s.empty, color: '#a0aec0' }}>{node.description}</div>
      )}

      {/* Host node — show stats and CVEs */}
      {!isSynthetic && (
        <>
          <div style={{ ...s.row, border: 'none' }}>
            <span style={s.label}>IP</span>
            <span style={s.val}>{node.ip || '-'}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Privilege</span>
            <span style={s.val}>{node.privilege}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Zone</span>
            <span style={s.val}>{node.zone}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Type</span>
            <span style={s.val}>{node.asset_type}</span>
          </div>
          <div style={{ ...s.riskBig, color: riskColor }}>
            {((node.risk_score || 0) * 100).toFixed(0)}% risk
          </div>
          <div style={s.row}>
            <span style={s.label}>Criticality</span>
            <span style={s.val}>{(node.criticality || 0).toFixed(2)}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Vulns</span>
            <span style={s.val}>{node.vuln_count || 0}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Max CVSS</span>
            <span style={s.val}>{(node.max_cvss || 0).toFixed(1)}</span>
          </div>
          <div style={s.row}>
            <span style={s.label}>Exploit</span>
            <span style={{ ...s.val, color: node.has_exploit ? '#ff4757' : '#2ed573' }}>
              {node.has_exploit ? 'Yes' : 'No'}
            </span>
          </div>

          {/* CVE list — top 5 by CVSS */}
          {topVulns.length > 0 && (
            <div style={s.cveSection}>
              <div style={s.cveHeader}>
                Top {topVulns.length} CVEs / Findings
              </div>
              {topVulns.map((v, i) => {
                const c = cvssColor(v.cvss)
                return (
                  <div key={i} style={s.cveItem}>
                    <span style={s.cveId} title={v.name}>
                      {v.vuln_id || v.name}
                    </span>
                    <span style={{ ...s.cveCvss, background: c.bg, color: c.fg }}>
                      {v.cvss.toFixed(1)}
                    </span>
                    {v.exploit_available && (
                      <span style={s.cveExploit} title="Exploit available">
                        EXP
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* Misconfiguration flags */}
          {activeFlags.length > 0 && (
            <div style={s.flagSection}>
              <div style={{ ...s.cveHeader, marginBottom: 4 }}>
                Misconfiguration Flags
              </div>
              {activeFlags.map(f => (
                <span key={f} style={s.flagItem}>
                  {f.replace(/_/g, ' ').replace(/^has /, '')}
                </span>
              ))}
            </div>
          )}
        </>
      )}

      {/* Termination reason for absorbing nodes */}
      {node.termination_reason && (
        <div style={s.termReason}>
          <strong>Why path absorbs here:</strong>
          <br />
          {node.termination_reason}
        </div>
      )}

      {node.is_absorbing && !node.termination_reason && (
        <div style={{ color: '#ff4757', fontWeight: 600, marginTop: 6 }}>
          ★ CROWN JEWEL (Absorbing State)
        </div>
      )}
      {node.is_entry && !isSynthetic && (
        <div style={{ color: '#00d4ff', fontWeight: 600, marginTop: 6 }}>
          ◎ Entry Point
        </div>
      )}
    </div>
  )
}