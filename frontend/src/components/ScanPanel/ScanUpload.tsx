import React, { useState } from 'react'
import { useDispatch } from 'react-redux'
import { setScanJob } from '../../store/scanSlice'
import { startScan } from '../../api/graph'

const btnStyle: React.CSSProperties = {
  padding: '6px 14px', borderRadius: 4, fontSize: 11, fontWeight: 600,
  cursor: 'pointer', border: '1px solid #7b61ff', background: '#7b61ff20',
  color: '#7b61ff', transition: 'all 0.2s',
}

export function ScanUpload() {
  const dispatch = useDispatch()
  const [loading, setLoading] = useState(false)

  async function handleLabDemo() {
    setLoading(true)
    try {
      const data = await startScan(true, 300)
      dispatch(setScanJob(data.job_id))
    } catch (e) {
      console.error('Scan failed:', e)
    }
    setLoading(false)
  }

  return (
    <button style={{ ...btnStyle, opacity: loading ? 0.5 : 1 }} onClick={handleLabDemo} disabled={loading}>
      {loading ? 'Starting...' : '▶ Run Lab Scan'}
    </button>
  )
}
