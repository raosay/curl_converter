import { useEffect, useMemo, useState } from 'react'
import { toJsonObjectWarn, type JSONOutput } from 'curlconverter'
import './App.css'

type KeyValue = {
  id: string
  key: string
  value: string
  enabled: boolean
}

type BodyType = 'none' | 'json' | 'text' | 'form'

type BodyState = {
  type: BodyType
  text: string
  form: KeyValue[]
}

type RequestState = {
  method: string
  protocol: string
  host: string
  path: string
  headers: KeyValue[]
  queryParams: KeyValue[]
  body: BodyState
  auth: { user: string; password: string } | null
  compressed: boolean
  insecure: boolean
  followRedirects?: boolean
  maxRedirects?: number
  timeout?: number
  proxy?: string
  include?: boolean
}

type ResponseState = {
  status: number
  statusText: string
  ok: boolean
  duration: number
  headers: KeyValue[]
  body: string
}

type KeyValueField = 'key' | 'value' | 'enabled'

type ProxySuccessResponse = {
  status: number
  statusText: string
  ok: boolean
  headers: Record<string, string>
  body: string
}

type ProxyErrorResponse = {
  error: string
}

const isProxyError = (
  payload: ProxySuccessResponse | ProxyErrorResponse,
): payload is ProxyErrorResponse => 'error' in payload

const FORWARD_HEADER_BLACKLIST = new Set(['host', 'connection', 'content-length'])

type StoredRequest = {
  id: string
  createdAt: number
  title: string
  request: RequestState
  response?: {
    status: number
    statusText: string
  }
  curl: string
}

type HistorySummary = {
  id: string
  title: string
  createdAt: number
  method: string
  url: string
  status?: number
  statusText?: string
}

const DB_NAME = 'curl-converter'
const DB_VERSION = 1
const STORE_NAME = 'histories'

const generateId = (): string => {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return Math.random().toString(36).slice(2)
}

const encodeBasicAuth = (value: string): string => {
  if (typeof btoa === 'function') {
    return btoa(value)
  }
  return value
}

const escapeSingleQuotes = (value: string): string => value.replace(/'/g, "\\'")

const formatTimestamp = (value: number): string => {
  const date = new Date(value)
  const pad = (num: number) => num.toString().padStart(2, '0')
  const year = date.getFullYear()
  const month = pad(date.getMonth() + 1)
  const day = pad(date.getDate())
  const hours = pad(date.getHours())
  const minutes = pad(date.getMinutes())
  const seconds = pad(date.getSeconds())
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
}

const normalizePath = (value: string): string => {
  if (!value) return ''
  return value.startsWith('/') ? value : `/${value}`
}

const recordToRows = (record?: Record<string, string | null>): KeyValue[] => {
  if (!record) return []
  return Object.entries(record)
    .filter(([, value]) => value !== null && value !== undefined)
    .map(([key, value]) => ({
      id: generateId(),
      key,
      value: value ?? '',
      enabled: true,
    }))
}

const queryToRows = (record?: Record<string, string | string[]>): KeyValue[] => {
  if (!record) return []
  const rows: KeyValue[] = []
  Object.entries(record).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((item) => {
        rows.push({ id: generateId(), key, value: String(item), enabled: true })
      })
    } else {
      rows.push({ id: generateId(), key, value: String(value), enabled: true })
    }
  })
  return rows
}

const ensureFormRows = (rows: KeyValue[]): KeyValue[] => {
  if (rows.length) return rows
  return [{ id: generateId(), key: '', value: '', enabled: true }]
}

const deriveBodyState = (data: JSONOutput['data'], contentType: string): BodyState => {
  const lowerContentType = contentType.toLowerCase()
  if (data === undefined || data === null) {
    return { type: 'none', text: '', form: [] }
  }

  if (lowerContentType.includes('application/x-www-form-urlencoded')) {
    const rows: KeyValue[] = []
    if (typeof data === 'object') {
      Object.entries(data as Record<string, unknown>).forEach(([key, value]) => {
        if (Array.isArray(value)) {
          value.forEach((item) => {
            rows.push({ id: generateId(), key, value: String(item), enabled: true })
          })
        } else {
          rows.push({ id: generateId(), key, value: String(value), enabled: true })
        }
      })
    }
    return { type: 'form', text: '', form: ensureFormRows(rows) }
  }

  if (typeof data === 'object') {
    return {
      type: 'json',
      text: JSON.stringify(data, null, 2),
      form: [],
    }
  }

  const text = typeof data === 'string' ? data : JSON.stringify(data)

  if (lowerContentType.includes('application/json')) {
    try {
      const parsed = JSON.parse(text)
      return {
        type: 'json',
        text: JSON.stringify(parsed, null, 2),
        form: [],
      }
    } catch {
      return { type: 'text', text, form: [] }
    }
  }

  if (text.length) {
    return { type: 'text', text, form: [] }
  }

  return { type: 'none', text: '', form: [] }
}

const convertCurlJsonToState = (json: JSONOutput): RequestState => {
  const candidate = json.raw_url || json.url
  let parsed: URL | null = null
  if (candidate) {
    try {
      parsed = new URL(candidate)
    } catch {
      try {
        parsed = new URL(`https://${candidate.replace(/^\/\//, '')}`)
      } catch {
        parsed = null
      }
    }
  }

  let host = ''
  let path = ''
  if (parsed) {
    host = parsed.host
    path = parsed.pathname
  } else if (candidate) {
    const [head, ...rest] = candidate.split('/')
    host = head
    path = rest.length ? `/${rest.join('/')}` : ''
  }

  const headers = recordToRows(json.headers)
  if (json.cookies && !headers.some((row) => row.key.toLowerCase() === 'cookie')) {
    const cookieValue = Object.entries(json.cookies)
      .map(([key, value]) => `${key}=${value}`)
      .join('; ')
    headers.push({ id: generateId(), key: 'Cookie', value: cookieValue, enabled: true })
  }

  const contentType = headers.find((row) => row.key.toLowerCase() === 'content-type')?.value ?? ''

  return {
    method: (json.method || 'GET').toUpperCase(),
    protocol: parsed?.protocol.replace(':', '') || 'https',
    host,
    path,
    headers,
    queryParams: queryToRows(json.queries),
    body: deriveBodyState(json.data, contentType),
    auth: json.auth ? { user: json.auth.user, password: json.auth.password } : null,
    compressed: Boolean(json.compressed),
    insecure: json.insecure === false,
    followRedirects: json.follow_redirects,
    maxRedirects: json.max_redirects,
    timeout: json.timeout,
    proxy: json.proxy,
    include: json.include,
  }
}

const getHeaderValue = (headers: KeyValue[], key: string): string | undefined => {
  const target = key.toLowerCase()
  const found = headers.find((row) => row.key.toLowerCase() === target)
  return found?.value
}

const upsertHeader = (headers: KeyValue[], key: string, value: string): KeyValue[] => {
  const target = key.toLowerCase()
  const index = headers.findIndex((row) => row.key.toLowerCase() === target)
  if (index >= 0) {
    const next = [...headers]
    next[index] = { ...next[index], value, enabled: true }
    return next
  }
  return [...headers, { id: generateId(), key, value, enabled: true }]
}

const hasEnabledValue = (row: KeyValue): boolean => row.enabled && row.key.trim().length > 0

const sanitizeHeadersForProxy = (
  headers: Record<string, string>,
  compressed: boolean,
): Record<string, string> => {
  const result: Record<string, string> = {}
  Object.entries(headers).forEach(([key, value]) => {
    if (!key) return
    const normalizedKey = key.trim()
    if (!normalizedKey) return
    const lower = normalizedKey.toLowerCase()
    if (FORWARD_HEADER_BLACKLIST.has(lower)) return
    result[normalizedKey] = value
  })
  if (compressed && !Object.keys(result).some((key) => key.toLowerCase() === 'accept-encoding')) {
    result['Accept-Encoding'] = 'gzip, deflate, br'
  }
  return result
}

const cloneRequestState = (state: RequestState): RequestState => {
  if (typeof structuredClone === 'function') {
    return structuredClone(state)
  }
  return JSON.parse(JSON.stringify(state)) as RequestState
}

const openDatabase = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' })
        store.createIndex('createdAt', 'createdAt', { unique: false })
      }
    }

    request.onsuccess = () => {
      resolve(request.result)
    }

    request.onerror = () => {
      reject(request.error)
    }
  })
}

const persistHistory = async (entry: StoredRequest) => {
  try {
    const db = await openDatabase()
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      store.put(entry)
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error)
    })
  } catch (error) {
    console.error('保存历史记录失败', error)
    throw error instanceof Error ? error : new Error('保存历史记录失败')
  }
}

const clearHistoriesStore = async () => {
  const db = await openDatabase()
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite')
    const store = transaction.objectStore(STORE_NAME)
    const request = store.clear()
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
  })
}

const fetchHistories = async (): Promise<HistorySummary[]> => {
  try {
    const db = await openDatabase()
    return await new Promise<HistorySummary[]>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const index = store.index('createdAt')
      const request = index.openCursor(null, 'prev')
      const result: HistorySummary[] = []

      request.onsuccess = () => {
        const cursor = request.result
        if (cursor) {
          const value = cursor.value as StoredRequest
          const url = `${value.request.protocol}://${value.request.host}${value.request.path}`
          result.push({
            id: value.id,
            title: value.title,
            createdAt: value.createdAt,
            method: value.request.method,
            url,
            status: value.response?.status,
            statusText: value.response?.statusText,
          })
          cursor.continue()
        }
      }

      transaction.oncomplete = () => resolve(result)
      transaction.onerror = () => reject(transaction.error)
    })
  } catch (error) {
    console.error('加载历史记录失败', error)
    throw error instanceof Error ? error : new Error('加载历史记录失败')
  }
}

const getHistoryById = async (id: string): Promise<StoredRequest | null> => {
  try {
    const db = await openDatabase()
    return await new Promise<StoredRequest | null>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.get(id)
      request.onsuccess = () => {
        resolve((request.result as StoredRequest | undefined) ?? null)
      }
      request.onerror = () => reject(request.error)
    })
  } catch (error) {
    console.error('获取历史记录详情失败', error)
    return null
  }
}

function App() {
  const [curlInput, setCurlInput] = useState('')
  const [request, setRequest] = useState<RequestState | null>(null)
  const [warnings, setWarnings] = useState<string[]>([])
  const [parseError, setParseError] = useState<string | null>(null)
  const [sending, setSending] = useState(false)
  const [response, setResponse] = useState<ResponseState | null>(null)
  const [sendError, setSendError] = useState<string | null>(null)
  const [histories, setHistories] = useState<HistorySummary[]>([])
  const [historyError, setHistoryError] = useState<string | null>(null)

  const handleImport = () => {
    if (!curlInput.trim()) {
      setParseError('请先粘贴 curl 命令')
      return
    }
    try {
      const [result, rawWarnings] = toJsonObjectWarn(curlInput)
      setRequest(convertCurlJsonToState(result))
      setWarnings(rawWarnings.map((item) => item[1]))
      setParseError(null)
      setSendError(null)
      setResponse(null)
    } catch (error) {
      const message = error instanceof Error ? error.message : '解析失败'
      setParseError(message)
      setWarnings([])
    }
  }

  const handleReset = () => {
    setRequest(null)
    setResponse(null)
    setWarnings([])
    setParseError(null)
    setSendError(null)
  }

  const updateKeyValue = (
    field: 'headers' | 'queryParams' | 'body',
    id: string,
    key: KeyValueField,
    value: string | boolean,
  ) => {
    setRequest((prev) => {
      if (!prev) return prev
      if (field === 'body') {
        const nextForm = prev.body.form.map((row) =>
          row.id === id
            ? {
                ...row,
                [key]: key === 'enabled' ? Boolean(value) : String(value),
              }
            : row,
        ) as KeyValue[]
        return {
          ...prev,
          body: { ...prev.body, form: nextForm },
        }
      }
      const nextRows = prev[field].map((row) =>
        row.id === id
          ? {
              ...row,
              [key]: key === 'enabled' ? Boolean(value) : String(value),
            }
          : row,
      )
      return {
        ...prev,
        [field]: nextRows,
      }
    })
  }

  const addRow = (field: 'headers' | 'queryParams' | 'body') => {
    const newRow: KeyValue = { id: generateId(), key: '', value: '', enabled: true }
    setRequest((prev) => {
      if (!prev) return prev
      if (field === 'body') {
        return {
          ...prev,
          body: { ...prev.body, form: [...prev.body.form, newRow] },
        }
      }
      return {
        ...prev,
        [field]: [...prev[field], newRow],
      }
    })
  }

  const removeRow = (field: 'headers' | 'queryParams' | 'body', id: string) => {
    setRequest((prev) => {
      if (!prev) return prev
      if (field === 'body') {
        const filtered = prev.body.form.filter((row) => row.id !== id)
        return {
          ...prev,
          body: { ...prev.body, form: filtered.length ? filtered : ensureFormRows([]) },
        }
      }
      const filtered = prev[field].filter((row) => row.id !== id)
      return {
        ...prev,
        [field]: filtered,
      }
    })
  }

  const handleBodyTypeChange = (type: BodyType) => {
    setRequest((prev) => {
      if (!prev) return prev
      if (type === 'form') {
        return {
          ...prev,
          body: {
            type,
            text: '',
            form: ensureFormRows(prev.body.form.length ? prev.body.form : []),
          },
        }
      }
      if (type === 'none') {
        return {
          ...prev,
          body: { type, text: '', form: [] },
        }
      }
      return {
        ...prev,
        body: { type, text: prev.body.text, form: [] },
      }
    })
  }

  const preparedResponseBody = useMemo(() => {
    if (!response) return ''
    try {
      const parsed = JSON.parse(response.body)
      return JSON.stringify(parsed, null, 2)
    } catch {
      return response.body
    }
  }, [response])

  const loadHistories = async () => {
    try {
      const list = await fetchHistories()
      setHistories(list)
      setHistoryError(null)
    } catch (error) {
      const message = error instanceof Error ? error.message : '历史记录加载失败'
      setHistoryError(message)
    }
  }

  const clearHistories = async () => {
    if (!histories.length) return
    const confirmed = window.confirm('确认清空全部历史记录？该操作不可恢复。')
    if (!confirmed) return
    try {
      await clearHistoriesStore()
      setHistories([])
      setHistoryError(null)
    } catch (error) {
      const message = error instanceof Error ? error.message : '清空历史记录失败'
      setHistoryError(message)
    }
  }

  useEffect(() => {
    void loadHistories()
  }, [])

  const restoreFromHistory = async (id: string) => {
    const record = await getHistoryById(id)
    if (!record) {
      setHistoryError('未找到对应的历史记录，请刷新后重试')
      return
    }
    setHistoryError(null)
    setRequest(cloneRequestState(record.request))
    setCurlInput(record.curl)
    setResponse(null)
    setSendError(null)
    setWarnings([])
  }

  const saveHistory = async (
    requestState: RequestState,
    curlText: string,
    responseState?: ResponseState | null,
  ) => {
    const snapshot = cloneRequestState(requestState)
    const url = `${snapshot.protocol}://${snapshot.host}${snapshot.path}`
    const entry: StoredRequest = {
      id: generateId(),
      createdAt: Date.now(),
      title: `${snapshot.method} ${url}`,
      request: snapshot,
      response: responseState
        ? {
            status: responseState.status,
            statusText: responseState.statusText,
          }
        : undefined,
      curl: curlText,
    }
    try {
      await persistHistory(entry)
      setHistoryError(null)
      await loadHistories()
    } catch (error) {
      const message = error instanceof Error ? error.message : '保存历史记录失败'
      setHistoryError(message)
    }
  }

  const sendRequest = async () => {
    if (!request) return

    const host = request.host.trim()
    if (!host) {
      setSendError('请填写有效的主机地址')
      return
    }

    const path = normalizePath(request.path)
    const baseUrl = `${request.protocol || 'https'}://${host}${path}`

    let urlObject: URL
    try {
      urlObject = new URL(baseUrl)
    } catch {
      setSendError('组合后的 URL 无效，请检查协议、主机与路径')
      return
    }

    const searchParams = new URLSearchParams()
    request.queryParams.forEach((row) => {
      if (hasEnabledValue(row)) {
        searchParams.append(row.key.trim(), row.value)
      }
    })
    const queryString = searchParams.toString()
    urlObject.search = queryString

    let headers = request.headers
    if (request.body.type === 'form') {
      const hasContentType = !!getHeaderValue(headers, 'content-type')
      if (!hasContentType) {
        headers = upsertHeader(headers, 'Content-Type', 'application/x-www-form-urlencoded')
        setRequest((prev) => (prev ? { ...prev, headers } : prev))
      }
    }

    if (request.body.type === 'json' && request.body.text.trim()) {
      try {
        JSON.parse(request.body.text)
      } catch {
        setSendError('JSON 请求体格式不正确，请检查后再试')
        return
      }
    }

    const headerMap: Record<string, string> = {}
    headers
      .filter(hasEnabledValue)
      .forEach((row) => {
        headerMap[row.key.trim()] = row.value
      })

    if (request.auth && (request.auth.user || request.auth.password)) {
      const hasAuthHeader = Object.keys(headerMap).some(
        (key) => key.toLowerCase() === 'authorization',
      )
      if (!hasAuthHeader) {
        const token = encodeBasicAuth(`${request.auth.user || ''}:${request.auth.password || ''}`)
        headerMap.Authorization = `Basic ${token}`
      }
    }

    let bodyPayload: string | null = null
    if (!['GET', 'HEAD'].includes(request.method)) {
      if (request.body.type === 'json' || request.body.type === 'text') {
        bodyPayload = request.body.text
        if (
          request.body.type === 'json' &&
          !Object.keys(headerMap).some((key) => key.toLowerCase() === 'content-type')
        ) {
          headerMap['Content-Type'] = 'application/json'
        }
      } else if (request.body.type === 'form') {
        const params = new URLSearchParams()
        request.body.form.forEach((row) => {
          if (hasEnabledValue(row)) {
            params.append(row.key.trim(), row.value)
          }
        })
        bodyPayload = params.toString()
        if (!Object.keys(headerMap).some((key) => key.toLowerCase() === 'content-type')) {
          headerMap['Content-Type'] = 'application/x-www-form-urlencoded'
        }
      }
    }

    const sanitizedHeaders = sanitizeHeadersForProxy(headerMap, request.compressed)
    const requestForHistory: RequestState = { ...request, headers }

    const serializedCurl = (() => {
      const parts = ['curl', '-X', request.method]
      Object.entries(sanitizedHeaders).forEach(([key, value]) => {
        const headerLine = `'${key}: ${escapeSingleQuotes(value)}'`
        parts.push('-H', headerLine)
      })
      if (bodyPayload !== null) {
        const bodyLine = `'${escapeSingleQuotes(bodyPayload)}'`
        parts.push('--data', bodyLine)
      }
      if (request.insecure) {
        parts.push('--insecure')
      }
      if (request.compressed) {
        parts.push('--compressed')
      }
      const qs = urlObject.searchParams.toString()
      const searchSuffix = qs ? `?${qs}` : ''
      parts.push(`'${urlObject.origin}${urlObject.pathname}${searchSuffix}'`)
      return parts.join(' ')
    })()

    setSending(true)
    setSendError(null)
    setResponse(null)

    try {
      const startedAt = performance.now()
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: urlObject.toString(),
          method: request.method,
          headers: sanitizedHeaders,
          body: bodyPayload,
          insecure: request.insecure,
          timeout: request.timeout ?? null,
          compressed: request.compressed,
        }),
      })
      const duration = performance.now() - startedAt

      if (!res.ok) {
        const errorPayload = (await res.json().catch(() => ({}))) as ProxyErrorResponse
        setSendError(errorPayload.error || `代理请求失败：${res.status} ${res.statusText}`)
        await saveHistory(requestForHistory, serializedCurl, null)
        return
      }

      const payload = (await res.json()) as ProxySuccessResponse | ProxyErrorResponse
      if (isProxyError(payload)) {
        setSendError(payload.error)
        await saveHistory(requestForHistory, serializedCurl, null)
        return
      }

      const responseHeaders: KeyValue[] = Object.entries(payload.headers).map(([key, value]) => ({
        id: generateId(),
        key,
        value,
        enabled: true,
      }))

      const nextResponse: ResponseState = {
        status: payload.status,
        statusText: payload.statusText,
        ok: payload.ok,
        headers: responseHeaders,
        body: payload.body,
        duration,
      }
      setResponse(nextResponse)
      await saveHistory(requestForHistory, serializedCurl, nextResponse)
    } catch (error) {
      const message = error instanceof Error ? error.message : '请求失败'
      setSendError(message)
      await saveHistory(requestForHistory, serializedCurl, null)
    } finally {
      setSending(false)
    }
  }


  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>cURL 导入请求工具</h1>
          <p className="app-subtitle">粘贴 cURL 命令，解析后自由调整并直接发起 HTTP 请求</p>
        </div>
        <div className="header-actions">
          <button type="button" className="ghost" onClick={handleReset} disabled={!request}>
            重置会话
          </button>
        </div>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h2>cURL 命令</h2>
          <div className="inline-actions">
            <button type="button" onClick={handleImport}>
              解析命令
            </button>
          </div>
        </div>
        <textarea
          className="curl-input"
          placeholder="粘贴完整的 curl 命令，可包含头、参数与请求体"
          value={curlInput}
          onChange={(event) => setCurlInput(event.target.value)}
        />
        {parseError ? <p className="error-text">{parseError}</p> : null}
        {warnings.length ? (
          <ul className="warning-list">
            {warnings.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : null}
      </section>

      <div className="workspace">
        <div className="request-column">
          <section className="panel request-panel">
            <h2>请求配置</h2>
            {request ? (
              <div className="request-sections">
                <div className="section-block">
                  <h3>请求协议与地址</h3>
                  <div className="request-grid">
                    <label className="field">
                      <span>协议</span>
                      <select
                        value={request.protocol}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, protocol: event.target.value } : prev,
                          )
                        }
                      >
                        <option value="https">https</option>
                        <option value="http">http</option>
                      </select>
                    </label>
                    <label className="field">
                      <span>主机</span>
                      <input
                        value={request.host}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, host: event.target.value } : prev,
                          )
                        }
                        placeholder="例如 api.example.com"
                      />
                    </label>
                    <label className="field field-wide">
                      <span>路径</span>
                      <input
                        value={request.path}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev
                              ? { ...prev, path: normalizePath(event.target.value) }
                              : prev,
                          )
                        }
                        placeholder="例如 /v1/resource"
                      />
                    </label>
                    <label className="field">
                      <span>方法</span>
                      <select
                        value={request.method}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev
                              ? { ...prev, method: event.target.value.toUpperCase() }
                              : prev,
                          )
                        }
                      >
                        {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((method) => (
                          <option value={method} key={method}>
                            {method}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                </div>

                <div className="section-block">
                  <div className="section-header">
                    <h3>查询参数</h3>
                    <button type="button" className="ghost" onClick={() => addRow('queryParams')}>
                      新增参数
                    </button>
                  </div>
                  {request.queryParams.length ? (
                    <div className="kv-list">
                      {request.queryParams.map((row) => (
                        <div className="kv-row" key={row.id}>
                          <input
                            className="kv-input"
                            placeholder="键"
                            value={row.key}
                            onChange={(event) => updateKeyValue('queryParams', row.id, 'key', event.target.value)}
                          />
                          <input
                            className="kv-input"
                            placeholder="值"
                            value={row.value}
                            onChange={(event) => updateKeyValue('queryParams', row.id, 'value', event.target.value)}
                          />
                          <label className="kv-toggle">
                            <input
                              type="checkbox"
                              checked={row.enabled}
                              onChange={(event) => updateKeyValue('queryParams', row.id, 'enabled', event.target.checked)}
                            />
                            启用
                          </label>
                          <button
                            type="button"
                            className="ghost danger"
                            onClick={() => removeRow('queryParams', row.id)}
                          >
                            删除
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">当前没有解析到查询参数，可手动新增</p>
                  )}
                </div>

                <div className="section-block">
                  <div className="section-header">
                    <h3>请求头</h3>
                    <button type="button" className="ghost" onClick={() => addRow('headers')}>
                      新增请求头
                    </button>
                  </div>
                  {request.headers.length ? (
                    <div className="kv-list">
                      {request.headers.map((row) => (
                        <div className="kv-row" key={row.id}>
                          <input
                            className="kv-input"
                            placeholder="Header 名称"
                            value={row.key}
                            onChange={(event) => updateKeyValue('headers', row.id, 'key', event.target.value)}
                          />
                          <input
                            className="kv-input"
                            placeholder="Header 值"
                            value={row.value}
                            onChange={(event) => updateKeyValue('headers', row.id, 'value', event.target.value)}
                          />
                          <label className="kv-toggle">
                            <input
                              type="checkbox"
                              checked={row.enabled}
                              onChange={(event) => updateKeyValue('headers', row.id, 'enabled', event.target.checked)}
                            />
                            启用
                          </label>
                          <button
                            type="button"
                            className="ghost danger"
                            onClick={() => removeRow('headers', row.id)}
                          >
                            删除
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">当前没有请求头，可根据需求自行补充</p>
                  )}
                </div>

                <div className="section-block">
                  <h3>请求体</h3>
                  <div className="body-type">
                    <label>
                      <input
                        type="radio"
                        value="none"
                        checked={request.body.type === 'none'}
                        onChange={() => handleBodyTypeChange('none')}
                      />
                      不发送
                    </label>
                    <label>
                      <input
                        type="radio"
                        value="json"
                        checked={request.body.type === 'json'}
                        onChange={() => handleBodyTypeChange('json')}
                      />
                      JSON
                    </label>
                    <label>
                      <input
                        type="radio"
                        value="text"
                        checked={request.body.type === 'text'}
                        onChange={() => handleBodyTypeChange('text')}
                      />
                      原始文本
                    </label>
                    <label>
                      <input
                        type="radio"
                        value="form"
                        checked={request.body.type === 'form'}
                        onChange={() => handleBodyTypeChange('form')}
                      />
                      表单（x-www-form-urlencoded）
                    </label>
                  </div>
                  {request.body.type === 'form' ? (
                    <div className="kv-list">
                      {request.body.form.map((row) => (
                        <div className="kv-row" key={row.id}>
                          <input
                            className="kv-input"
                            placeholder="字段名"
                            value={row.key}
                            onChange={(event) => updateKeyValue('body', row.id, 'key', event.target.value)}
                          />
                          <input
                            className="kv-input"
                            placeholder="字段值"
                            value={row.value}
                            onChange={(event) => updateKeyValue('body', row.id, 'value', event.target.value)}
                          />
                          <label className="kv-toggle">
                            <input
                              type="checkbox"
                              checked={row.enabled}
                              onChange={(event) => updateKeyValue('body', row.id, 'enabled', event.target.checked)}
                            />
                            启用
                          </label>
                          <button
                            type="button"
                            className="ghost danger"
                            onClick={() => removeRow('body', row.id)}
                          >
                            删除
                          </button>
                        </div>
                      ))}
                      <button type="button" className="ghost" onClick={() => addRow('body')}>
                        新增字段
                      </button>
                    </div>
                  ) : request.body.type === 'none' ? (
                    <p className="muted">当前请求不包含请求体</p>
                  ) : (
                    <textarea
                      className="body-editor"
                      value={request.body.text}
                      onChange={(event) =>
                        setRequest((prev) =>
                          prev
                            ? { ...prev, body: { ...prev.body, text: event.target.value } }
                            : prev,
                        )
                      }
                      placeholder="在此编辑请求体内容"
                    />
                  )}
                </div>

                <div className="section-block">
                  <h3>认证与其他设置</h3>
                  <div className="option-grid">
                    <label className="field">
                      <span>用户名</span>
                      <input
                        value={request.auth?.user ?? ''}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev
                              ? {
                                  ...prev,
                                  auth: {
                                    user: event.target.value,
                                    password: prev.auth?.password ?? '',
                                  },
                                }
                              : prev,
                          )
                        }
                        placeholder="Basic Auth 用户名"
                      />
                    </label>
                    <label className="field">
                      <span>密码</span>
                      <input
                        value={request.auth?.password ?? ''}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev
                              ? {
                                  ...prev,
                                  auth: {
                                    user: prev.auth?.user ?? '',
                                    password: event.target.value,
                                  },
                                }
                              : prev,
                          )
                        }
                        placeholder="Basic Auth 密码"
                        type="password"
                      />
                    </label>
                    <label className="field">
                      <span>代理地址</span>
                      <input
                        value={request.proxy ?? ''}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, proxy: event.target.value } : prev,
                          )
                        }
                        placeholder="例如 http://proxy.local:8080"
                      />
                    </label>
                    <label className="field">
                      <span>超时时间（秒）</span>
                      <input
                        type="number"
                        min="0"
                        value={request.timeout ?? ''}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev
                              ? {
                                  ...prev,
                                  timeout: event.target.value
                                    ? Number(event.target.value)
                                    : undefined,
                                }
                              : prev,
                          )
                        }
                      />
                    </label>
                  </div>
                  <div className="checkbox-row">
                    <label>
                      <input
                        type="checkbox"
                        checked={request.compressed}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, compressed: event.target.checked } : prev,
                          )
                        }
                      />
                      发送压缩头（Accept-Encoding: gzip）
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={request.insecure}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, insecure: event.target.checked } : prev,
                          )
                        }
                      />
                      忽略 TLS 校验（等同 --insecure）
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={Boolean(request.followRedirects)}
                        onChange={(event) =>
                          setRequest((prev) =>
                            prev ? { ...prev, followRedirects: event.target.checked } : prev,
                          )
                        }
                      />
                      跟随重定向
                    </label>
                  </div>
                </div>

                <div className="section-block">
                  <button type="button" className="primary" onClick={sendRequest} disabled={sending}>
                    {sending ? '请求发送中…' : '发送请求'}
                  </button>
                  {sendError ? <p className="error-text">{sendError}</p> : null}
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p>请先在上方粘贴并解析 cURL 命令，解析后可在此处调整请求各项配置。</p>
              </div>
            )}
          </section>
        </div>

        <div className="response-column">
          <section className="panel history-panel">
            <div className="panel-header history-header">
              <h2>历史记录</h2>
              <div className="inline-actions">
                <button type="button" className="ghost" onClick={() => void loadHistories()}>
                  刷新
                </button>
                <button
                  type="button"
                  className="ghost danger"
                  onClick={() => void clearHistories()}
                  disabled={!histories.length}
                >
                  清空历史
                </button>
              </div>
            </div>
            {historyError ? <p className="error-text">{historyError}</p> : null}
            {histories.length ? (
              <ul className="history-list">
                {histories.map((item) => (
                  <li key={item.id} className="history-item">
                    <div className="history-top">
                      <span className={`method-badge method-${item.method.toLowerCase()}`}>
                        {item.method}
                      </span>
                      <span className="history-url" title={item.url}>
                        {item.url}
                      </span>
                    </div>
                    <div className="history-bottom">
                      <span className="history-time">{formatTimestamp(item.createdAt)}</span>
                      {typeof item.status === 'number' ? (
                        <span
                          className={`history-status ${item.status >= 200 && item.status < 400 ? 'success' : 'error'}`}
                        >
                          {item.status} {item.statusText ?? ''}
                        </span>
                      ) : (
                        <span className="history-status pending">未获取响应</span>
                      )}
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => void restoreFromHistory(item.id)}
                      >
                        回填
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">暂无历史记录，请先发送请求</p>
            )}
          </section>
          <section className="panel response-panel">
            <h2>响应结果</h2>
            {response ? (
              <div className="response-content">
                <div className="response-meta">
                  <span className={response.ok ? 'status success' : 'status error'}>
                    {response.status} {response.statusText}
                  </span>
                  <span className="duration">{response.duration.toFixed(0)} ms</span>
                </div>
                <div className="section-block">
                  <h3>响应头</h3>
                  {response.headers.length ? (
                    <ul className="header-list">
                      {response.headers.map((row) => (
                        <li key={row.id}>
                          <strong>{row.key}:</strong> <span>{row.value}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted">未返回任何响应头</p>
                  )}
                </div>
                <div className="section-block">
                  <h3>响应体</h3>
                  <pre className="response-body">{preparedResponseBody}</pre>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p>请求发送后的响应内容会显示在这里。</p>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  )
}

export default App
