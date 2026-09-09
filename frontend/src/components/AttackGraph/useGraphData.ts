import { useSelector } from 'react-redux'
import type { RootState } from '../../main'

export function useGraphData() {
  const graph = useSelector((s: RootState) => s.graph)
  return graph
}
