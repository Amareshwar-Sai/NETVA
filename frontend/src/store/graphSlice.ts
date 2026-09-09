import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { getGraph, getAssets } from '../api/graph'

interface GraphState {
  nodes: any[]
  edges: any[]
  assets: any[]   // per-asset CVE detail from /graph/assets
  loading: boolean
  error: string | null
}

const initialState: GraphState = {
  nodes: [],
  edges: [],
  assets: [],
  loading: false,
  error: null,
}

// Fetch graph topology AND per-asset CVE details in parallel
export const fetchGraph = createAsyncThunk('graph/fetch', async () => {
  const [graphData, assetsData] = await Promise.all([
    getGraph(),
    getAssets().catch(() => ({ assets: [] })),  // tolerate failure
  ])
  return {
    nodes: graphData.nodes,
    edges: graphData.edges,
    assets: assetsData.assets || [],
  }
})

export const graphSlice = createSlice({
  name: 'graph',
  initialState,
  reducers: {
    setGraph: (state, action) => {
      state.nodes = action.payload.nodes
      state.edges = action.payload.edges
      if (action.payload.assets) state.assets = action.payload.assets
    },
    clearGraph: (state) => {
      state.nodes = []
      state.edges = []
      state.assets = []
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchGraph.pending, (state) => {
        state.loading = true
        state.error = null
      })
      .addCase(fetchGraph.fulfilled, (state, action) => {
        state.loading = false
        state.nodes = action.payload.nodes
        state.edges = action.payload.edges
        state.assets = action.payload.assets
      })
      .addCase(fetchGraph.rejected, (state, action) => {
        state.loading = false
        state.error = action.error.message || 'Failed to fetch graph'
      })
  },
})

export const { setGraph, clearGraph } = graphSlice.actions