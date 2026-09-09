import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { getRemediation } from '../api/remediation'

interface RemediationState {
  steps: any[]
  policy: any | null
  executionLog: any[]
  loading: boolean
  error: string | null
}

const initialState: RemediationState = { steps: [], policy: null, executionLog: [], loading: false, error: null }

export const fetchRemediation = createAsyncThunk('remediation/fetch', async () => {
  const data = await getRemediation()
  return data
})

export const remediationSlice = createSlice({
  name: 'remediation',
  initialState,
  reducers: {
    addExecutionLog: (state, action) => { state.executionLog.push(action.payload) },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRemediation.pending, (s) => { s.loading = true; s.error = null })
      .addCase(fetchRemediation.fulfilled, (s, a) => {
        s.loading = false
        s.steps = a.payload.steps
        s.policy = a.payload
      })
      .addCase(fetchRemediation.rejected, (s, a) => { s.loading = false; s.error = a.error.message || 'Failed' })
  },
})

export const { addExecutionLog } = remediationSlice.actions
