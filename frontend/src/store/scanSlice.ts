import { createSlice } from '@reduxjs/toolkit'

interface ScanState {
  jobId: string
  status: string
  stage: string
  progress: number
  message: string
}

const initialState: ScanState = { jobId: '', status: 'idle', stage: '', progress: 0, message: '' }

export const scanSlice = createSlice({
  name: 'scan',
  initialState,
  reducers: {
    setScanJob: (state, action) => { state.jobId = action.payload; state.status = 'running' },
    updateScanProgress: (state, action) => {
      const { stage, progress, message, status } = action.payload
      if (stage !== undefined) state.stage = stage
      if (progress !== undefined) state.progress = progress
      if (message !== undefined) state.message = message
      if (status !== undefined) state.status = status
    },
    resetScan: () => initialState,
  },
})

export const { setScanJob, updateScanProgress, resetScan } = scanSlice.actions
