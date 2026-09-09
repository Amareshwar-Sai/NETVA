let ws: WebSocket | null = null

export function connectWebSocket(onMessage: (msg: any) => void): () => void {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/ws/live`

  function connect() {
    try {
      ws = new WebSocket(url)

      ws.onopen = () => {
        console.log('[WS] Connected')
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          onMessage(msg)
        } catch (e) {
          console.warn('[WS] Failed to parse message:', event.data)
        }
      }

      ws.onclose = () => {
        console.log('[WS] Disconnected, reconnecting in 3s...')
        setTimeout(connect, 3000)
      }

      ws.onerror = (err) => {
        console.warn('[WS] Error:', err)
        ws?.close()
      }
    } catch (e) {
      console.warn('[WS] Connection failed, retrying in 3s...')
      setTimeout(connect, 3000)
    }
  }

  connect()

  return () => {
    if (ws) {
      ws.onclose = null
      ws.close()
      ws = null
    }
  }
}
