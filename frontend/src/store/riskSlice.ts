import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { getRisk, getRiskPaths, getRiskSummary } from '../api/graph'

interface RiskState {
  stateMetrics: any[]
  criticalPaths: any[]
  summary: any | null
  loading: boolean
  error: string | null
  isSimulated: boolean  // true when current state is a simulation preview
}

const initialState: RiskState = {
  stateMetrics: [], criticalPaths: [], summary: null,
  loading: false, error: null, isSimulated: false,
}

export const fetchRisk = createAsyncThunk('risk/fetch', async () => {
  const [risk, paths, summary] = await Promise.all([
    getRisk(), getRiskPaths(), getRiskSummary(),
  ])
  return { stateMetrics: risk.state_metrics, criticalPaths: paths, summary }
})

export const riskSlice = createSlice({
  name: 'risk',
  initialState,
  reducers: {
    // Apply simulation results — replaces current risk view with preview
    applySimulation: (state, action) => {
      if (action.payload.stateMetrics) state.stateMetrics = action.payload.stateMetrics
      if (action.payload.criticalPaths) state.criticalPaths = action.payload.criticalPaths
      if (action.payload.summary) state.summary = action.payload.summary
      state.isSimulated = true
    },
    clearSimulation: (state) => {
      state.isSimulated = false
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRisk.pending, (s) => { s.loading = true; s.error = null })
      .addCase(fetchRisk.fulfilled, (s, a) => {
        s.loading = false
        s.stateMetrics = a.payload.stateMetrics
        s.criticalPaths = a.payload.criticalPaths
        s.summary = a.payload.summary
        s.isSimulated = false  // resetting to live data clears simulation flag
      })
      .addCase(fetchRisk.rejected, (s, a) => {
        s.loading = false
        s.error = a.error.message || 'Failed'
      })
  },
})

export const { applySimulation, clearSimulation } = riskSlice.actions