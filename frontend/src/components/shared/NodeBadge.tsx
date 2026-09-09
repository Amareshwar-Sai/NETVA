import React from 'react'

interface Props { label: string; type?: string }

const typeColors: Record<string, string> = {
  webserver: '#00d4ff', appserver: '#7b61ff', database: '#ff4757',
  firewall: '#ffa502', external: '#5a6580',
}

export function NodeBadge({ label, type = 'server' }: Props) {
  const color = typeColors[type] || '#8892a6'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 3,
      fontSize: 10, fontWeight: 600, background: `${color}20`, color, border: `1px solid ${color}40`,
    }}>
      {label}
    </span>
  )
}
