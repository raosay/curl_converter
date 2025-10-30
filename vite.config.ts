import { defineConfig, type PluginOption } from 'vite'
import react from '@vitejs/plugin-react'
import { Agent, type RequestInit } from 'undici'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { setTimeout as setNodeTimeout, clearTimeout as clearNodeTimeout } from 'node:timers'

type ProxyPayload = {
  url?: string
  method?: string
  headers?: Record<string, string>
  body?: string | null
  insecure?: boolean
  timeout?: number | null
  compressed?: boolean
}

type ProxyResult = {
  status: number
  statusText: string
  headers: Record<string, string>
  body: string
  ok: boolean
}

type ProxyError = {
  error: string
}

type ProxyResponse = ProxyResult | ProxyError

const DISALLOWED_HEADERS = new Set(['accept-encoding', 'connection', 'content-length', 'host'])

const sendJson = (res: ServerResponse, statusCode: number, payload: ProxyResponse) => {
  const body = JSON.stringify(payload)
  res.statusCode = statusCode
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('access-control-allow-origin', '*')
  res.setHeader('access-control-allow-headers', 'content-type')
  res.end(body)
}

const readRequestBody = (req: IncomingMessage): Promise<string> => {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk) => {
      if (chunk instanceof Buffer) {
        chunks.push(chunk)
      } else {
        chunks.push(Buffer.from(chunk))
      }
    })
    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf-8'))
    })
    req.on('error', reject)
  })
}

const createProxyMiddleware = () => {
  return async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === 'OPTIONS') {
      res.statusCode = 204
      res.setHeader('access-control-allow-origin', '*')
      res.setHeader('access-control-allow-headers', 'content-type')
      res.setHeader('access-control-allow-methods', 'POST, OPTIONS')
      res.end()
      return
    }

    if (req.method !== 'POST') {
      sendJson(res, 405, { error: '仅支持 POST 请求' })
      return
    }

    let payload: ProxyPayload
    try {
      const raw = await readRequestBody(req)
      payload = raw ? (JSON.parse(raw) as ProxyPayload) : {}
    } catch (error) {
      sendJson(res, 400, { error: '请求体解析失败' })
      return
    }

    if (!payload.url) {
      sendJson(res, 400, { error: '缺少目标地址' })
      return
    }

    let target: URL
    try {
      target = new URL(payload.url)
    } catch {
      sendJson(res, 400, { error: '目标地址格式不正确' })
      return
    }

    if (!['http:', 'https:'].includes(target.protocol)) {
      sendJson(res, 400, { error: '仅支持 http 与 https 协议' })
      return
    }

    const method = (payload.method || 'GET').toUpperCase()
    const headers: Record<string, string> = {}
    if (payload.headers) {
      for (const [key, value] of Object.entries(payload.headers)) {
        if (!key) continue
        const lower = key.toLowerCase()
        if (DISALLOWED_HEADERS.has(lower)) continue
        if (typeof value !== 'string') continue
        headers[key] = value
      }
    }

    if (payload.compressed && !Object.keys(headers).some((key) => key.toLowerCase() === 'accept-encoding')) {
      headers['Accept-Encoding'] = 'gzip, deflate, br'
    }

    const controller = new AbortController()
    let timeoutId: NodeJS.Timeout | null = null
    const timeoutMs = typeof payload.timeout === 'number' && payload.timeout > 0 ? payload.timeout * 1000 : null
    if (timeoutMs) {
      timeoutId = setNodeTimeout(() => {
        controller.abort(new Error('请求已超时'))
      }, timeoutMs)
    }

    const dispatcher = payload.insecure && target.protocol === 'https:'
      ? new Agent({
          connect: {
            rejectUnauthorized: false,
          },
        })
      : undefined

    try {
      const init: RequestInit = {
        method,
        headers,
        signal: controller.signal,
        dispatcher,
      }

      if (!['GET', 'HEAD'].includes(method) && typeof payload.body === 'string') {
        init.body = payload.body
      }

      const upstream = await fetch(target.toString(), init)
      const text = await upstream.text()
      const responseHeaders: Record<string, string> = {}
      upstream.headers.forEach((value, key) => {
        responseHeaders[key] = value
      })

      sendJson(res, 200, {
        status: upstream.status,
        statusText: upstream.statusText,
        body: text,
        headers: responseHeaders,
        ok: upstream.ok,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : '请求代理失败'
      if (message.includes('aborted')) {
        sendJson(res, 504, { error: '上游请求超时' })
      } else {
        sendJson(res, 502, { error: message })
      }
    } finally {
      if (timeoutId) {
        clearNodeTimeout(timeoutId)
      }
      void dispatcher?.close()
    }
  }
}

const proxyPlugin = (): PluginOption => {
  return {
    name: 'curl-converter-proxy',
    configureServer(server) {
      const handler = createProxyMiddleware()
      server.middlewares.use('/api/proxy', handler)
    },
    configurePreviewServer(server) {
      const handler = createProxyMiddleware()
      server.middlewares.use('/api/proxy', handler)
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), proxyPlugin()],
})
