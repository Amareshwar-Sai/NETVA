import React from 'react'
import ReactDOM from 'react-dom/client'
import { Provider } from 'react-redux'
import { configureStore } from '@reduxjs/toolkit'
import App from './App'
import { graphSlice } from './store/graphSlice'
import { riskSlice } from './store/riskSlice'
import { remediationSlice } from './store/remediationSlice'
import { scanSlice } from './store/scanSlice'

const store = configureStore({
  reducer: {
    graph: graphSlice.reducer,
    risk: riskSlice.reducer,
    remediation: remediationSlice.reducer,
    scan: scanSlice.reducer,
  },
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Provider store={store}>
      <App />
    </Provider>
  </React.StrictMode>,
)
