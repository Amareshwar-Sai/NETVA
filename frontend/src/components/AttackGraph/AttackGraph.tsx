import React, { useRef, useEffect, useState } from 'react'
import { useSelector } from 'react-redux'
import * as d3 from 'd3'
import type { RootState } from '../../main'
import { NodeTooltip } from './NodeTooltip'

const styles: Record<string, React.CSSProperties> = {
  container: {
    position: 'relative', width: '100%', height: 420,
    background: '#080c14', borderRadius: 8, overflow: 'hidden',
  },
  empty: {
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    height: '100%', color: '#3a4560', fontSize: 13,
  },
}

export function AttackGraph() {
  const svgRef = useRef<SVGSVGElement>(null)
  const { nodes, edges, assets, loading } = useSelector((s: RootState) => s.graph)
  const [tooltip, setTooltip] = useState<any>(null)
  const [tooltipAsset, setTooltipAsset] = useState<any>(null)

  // Find the matching asset for a clicked node by IP
  const findAssetForNode = (node: any) => {
    if (!node || !assets || assets.length === 0) return null
    const nodeIp = node.ip || node.host_id
    if (!nodeIp) return null
    return assets.find((a: any) => a.ip === nodeIp || a.asset_id === nodeIp) || null
  }

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    const g = svg.append('g')

    // Zoom
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => g.attr('transform', event.transform))
    svg.call(zoom)

    // Color scale: risk 1.0 → red, 0.0 → green
    const colorScale = d3.scaleSequential(d3.interpolateRdYlGn).domain([1, 0])

    // Build links/nodes for simulation
    const simNodes = nodes.map((n: any) => ({ ...n, id: n.state_id }))
    const simLinks = edges.map((e: any) => ({ ...e, source: e.source, target: e.target }))

    // Edges
    const link = g.append('g')
      .selectAll('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', (d: any) => {
        if (d.edge_type === 'lateral_movement') return '#7b61ff'
        if (d.edge_type === 'perimeter_traversal') return '#00d4ff'
        if (d.edge_type === 'perimeter_bypass') return '#ffa502'
        if (d.edge_type === 'fw_approach') return '#5a6580'
        if (d.edge_type === 'network_exploit_via_fw') return '#ff7a90'
        return '#1e3a5f'
      })
      .attr('stroke-width', (d: any) => 1 + (d.weight || 0.5) * 2)
      .attr('stroke-dasharray', (d: any) => {
        if (d.edge_type === 'lateral_movement') return '6 3'
        if (d.edge_type === 'fw_approach') return '3 3'
        return 'none'
      })
      .attr('opacity', 0.6)

    // Nodes
    const node = g.append('g')
      .selectAll('g')
      .data(simNodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(d3.drag<any, any>()
        .on('start', (e, d: any) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (e, d: any) => { d.fx = e.x; d.fy = e.y })
        .on('end', (e, d: any) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null })
      )

    // Node shapes
    node.each(function (d: any) {
      const el = d3.select(this)
      const r = 8 + (d.criticality || 0) * 12

      // Synthetic node colors
      let color: string
      if (d.node_role === 'entry') {
        color = '#00d4ff'
      } else if (d.node_role === 'defense') {
        color = '#ffa502'  // orange — defense layers
      } else {
        color = colorScale(d.risk_score || 0) as string
      }

      if (d.node_role === 'defense') {
        // Hexagon-ish for defense layers (use rect rotated 45)
        const size = r * 1.6
        el.append('rect')
          .attr('width', size).attr('height', size)
          .attr('x', -size / 2).attr('y', -size / 2)
          .attr('rx', 4).attr('ry', 4)
          .attr('fill', color)
          .attr('stroke', '#fff')
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '4 2')
      } else if (d.is_absorbing) {
        // Diamond for absorbing
        const size = r * 1.5
        el.append('rect')
          .attr('width', size).attr('height', size)
          .attr('x', -size / 2).attr('y', -size / 2)
          .attr('transform', 'rotate(45)')
          .attr('fill', color).attr('stroke', '#fff').attr('stroke-width', 1.5)
      } else if (d.is_entry || d.node_role === 'entry') {
        // Ring + circle for entry
        el.append('circle').attr('r', r + 4).attr('fill', 'none').attr('stroke', '#00d4ff').attr('stroke-width', 1.5)
        el.append('circle').attr('r', r).attr('fill', color)
      } else {
        el.append('circle').attr('r', r).attr('fill', color).attr('stroke', '#1e3a5f').attr('stroke-width', 1)
      }

      // Label — prefer hostname, fall back to label/host_id
      const labelText = d.hostname || d.label || d.host_id || ''
      el.append('text')
        .text(labelText)
        .attr('dy', r + 14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#6b7a99')
        .attr('font-size', 9)
        .attr('font-family', 'JetBrains Mono, monospace')

      // Privilege badge for host nodes
      if (d.node_role === 'host' && d.privilege && d.privilege !== 'none') {
        el.append('text')
          .text(`[${d.privilege}]`)
          .attr('dy', r + 25)
          .attr('text-anchor', 'middle')
          .attr('fill', '#5a6580')
          .attr('font-size', 8)
          .attr('font-family', 'JetBrains Mono, monospace')
      }
    })

    node.on('click', (_e: any, d: any) => {
      setTooltip(d)
      setTooltipAsset(findAssetForNode(d))
    })

    // Force simulation
    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id((d: any) => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-900))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide(50))

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`)
    })

    return () => { simulation.stop() }
  }, [nodes, edges])

  if (loading) return <div style={styles.container}><div style={styles.empty}>Loading graph...</div></div>
  if (nodes.length === 0) return <div style={styles.container}><div style={styles.empty}>Run a scan to generate the attack graph</div></div>

  return (
    <div style={styles.container}>
      <svg ref={svgRef} width="100%" height="100%" />
      {tooltip && (
        <NodeTooltip
          node={tooltip}
          asset={tooltipAsset}
          onClose={() => { setTooltip(null); setTooltipAsset(null) }}
        />
      )}
    </div>
  )
}