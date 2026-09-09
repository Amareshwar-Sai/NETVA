import React from 'react'

export function Spinner({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" style={{ animation: 'spin 1s linear infinite' }}>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" stroke="#1e2a42" strokeWidth="3" fill="none" />
      <path d="M12 2 A10 10 0 0 1 22 12" stroke="#7b61ff" strokeWidth="3" fill="none" strokeLinecap="round" />
    </svg>
  )
}
