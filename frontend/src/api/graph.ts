import client from './client'

export async function getGraph() {
  const { data } = await client.get('/graph')
  return data
}

export async function getAssets() {
  const { data } = await client.get('/graph/assets')
  return data
}

export async function getRisk() {
  const { data } = await client.get('/risk')
  return data
}

export async function getRiskPaths() {
  const { data } = await client.get('/risk/paths')
  return data
}

export async function getRiskSummary() {
  const { data } = await client.get('/risk/summary')
  return data
}

export async function startScan(useLabDefaults = true, episodes = 300) {
  const { data } = await client.post('/scan', { use_lab_defaults: useLabDefaults, episodes })
  return data
}

export async function getScanStatus(jobId: string) {
  const { data } = await client.get(`/scan/${jobId}`)
  return data
}
