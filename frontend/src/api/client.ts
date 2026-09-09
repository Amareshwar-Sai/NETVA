import axios from 'axios'

export const API_BASE = ''

const client = axios.create({
  baseURL: API_BASE,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
})

export default client
