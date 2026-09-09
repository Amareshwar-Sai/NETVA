import React from 'react'

interface Props { score: number }

export function RiskBadge({ score }: Props) {
  const color = score >= 0.7 ? '#ff4757' : score >= 0.4 ? '#ffa502' : '#2ed573'
  const label = score >= 0.7 ? 'CRITICAL' : score >= 0.4 ? 'HIGH' : score >= 0.2 ? 'MEDIUM' : 'LOW'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 3,
      fontSize: 10, fontWeight: 700, background: `${color}20`, color,
    }}>
      {label} ({(score * 100).toFixed(0)}%)
    </span>
  )
}
