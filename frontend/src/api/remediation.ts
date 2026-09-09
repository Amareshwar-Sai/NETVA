import client from './client'

export async function getRemediation() {
  const { data } = await client.get('/remediation')
  return data
}

export async function getActionCatalogue() {
  const { data } = await client.get('/remediation/actions')
  return data
}

export async function simulateAction(actionId: string, targetAssetId: string) {
  const { data } = await client.post('/remediation/simulate', {
    action_id: actionId,
    target_asset_id: targetAssetId,
  })
  return data
}

export async function executeAction(actionId: string, targetAssetId: string, dryRun = true) {
  const { data } = await client.post('/execute', {
    action_id: actionId,
    target_asset_id: targetAssetId,
    dry_run: dryRun,
  })
  return data
}

export async function resetSimulation() {
  const { data } = await client.post('/remediation/reset')
  return data
}
