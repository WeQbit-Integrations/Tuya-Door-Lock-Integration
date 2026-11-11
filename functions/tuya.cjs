const crypto = require('node:crypto')

function canonicalTuyaPath(path) {
  const url = new URL(path, 'https://tuya.invalid')
  url.searchParams.sort()
  return `${url.pathname}${url.search}`
}

function signRequest({ clientId, secret, token = '', timestamp, nonce = '', method, path, body = '' }) {
  const hash = crypto.createHash('sha256').update(body).digest('hex')
  const stringToSign = `${method}\n${hash}\n\n${path}`
  return crypto.createHmac('sha256', secret).update(`${clientId}${token}${timestamp}${nonce}${stringToSign}`).digest('hex').toUpperCase()
}

function encryptPin(pin, encryptedTicket, secret) {
  const key = Buffer.from(secret, 'utf8')
  if (key.length !== 32) throw new Error('Tuya client secret must be 32 bytes')
  const decipher = crypto.createDecipheriv('aes-256-ecb', key, null)
  const ticketKey = Buffer.concat([decipher.update(Buffer.from(encryptedTicket, 'hex')), decipher.final()])
  if (ticketKey.length !== 16) throw new Error('Invalid Tuya ticket key')
  const cipher = crypto.createCipheriv('aes-128-ecb', ticketKey, null)
  return Buffer.concat([cipher.update(pin, 'utf8'), cipher.final()]).toString('hex').toUpperCase()
}

function normalizePasswords(result) {
  if (!Array.isArray(result)) throw new Error('Unexpected temporary password list from Tuya')
  return result.map((entry) => {
    const rawId = entry.password_id ?? entry.id
    const passwordId = typeof rawId === 'string' ? rawId : Number.isSafeInteger(rawId) ? String(rawId) : ''
    const start = Number(entry.effective_time)
    const end = Number(entry.invalid_time)
    if (!/^\d+$/.test(passwordId) || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start <= 0 || end <= 0) {
      throw new Error('Invalid temporary password metadata from Tuya')
    }
    return {
      passwordId,
      name: typeof entry.name === 'string' && entry.name.trim() ? entry.name.trim() : 'Unnamed visitor',
      start,
      end,
      state: ({ 0: 'revoked', 1: 'pending', 2: 'delivered', 3: 'revoking' })[entry.phase] || 'unknown',
    }
  })
}

function normalizeOfflinePasswords(result, page = 1) {
  if (!Array.isArray(result?.records)) throw new Error('Unexpected offline password list from Tuya')
  const total = Number(result.total ?? result.records.length)
  if (!Number.isSafeInteger(total) || total < result.records.length) throw new Error('Invalid offline password count from Tuya')
  const statuses = { 1: 'generated', 2: 'used', 3: 'invalid' }
  const records = result.records.flatMap((entry) => {
    if (entry.pwd_type_code && entry.pwd_type_code !== 'once') return []
    const rawId = entry.pwd_id
    const passwordId = typeof rawId === 'string' ? rawId : Number.isSafeInteger(rawId) ? String(rawId) : ''
    const start = Number(entry.gmt_start)
    const end = Number(entry.gmt_expired)
    const createdAt = Number(entry.gmt_create)
    if (!/^\d{1,40}$/.test(passwordId) || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start <= 0 || end <= 0) {
      throw new Error('Invalid offline password metadata from Tuya')
    }
    return [{
      id: `tuya-${passwordId}`,
      passwordId,
      name: typeof entry.pwd_name === 'string' && entry.pwd_name.trim() ? entry.pwd_name.trim() : 'Unnamed visitor',
      type: typeof entry.pwd_type_code === 'string' ? entry.pwd_type_code : 'once',
      start,
      end,
      ...(Number.isSafeInteger(createdAt) && createdAt > 0 ? { createdAt } : {}),
      passwordType: Number.isSafeInteger(Number(entry.pwd_type)) ? Number(entry.pwd_type) : null,
      statusCode: Number.isSafeInteger(Number(entry.status)) ? Number(entry.status) : null,
      hasClearPassword: typeof entry.has_clear_pwd === 'boolean' ? entry.has_clear_pwd : null,
      timeZone: typeof entry.time_zone_id === 'string' ? entry.time_zone_id : '',
      state: statuses[Number(entry.status)] || 'unknown',
      sourceTuya: true,
    }]
  })
  const totalPages = Number(result.total_pages)
  const hasMore = typeof result.has_more === 'boolean' ? result.has_more : Number.isSafeInteger(totalPages) && totalPages > page
  return { records, total, hasMore }
}

function normalizeUnlockLogs(result) {
  if (!Array.isArray(result?.logs) || !Number.isSafeInteger(result.total) || result.total < 0) throw new Error('Unexpected unlock history from Tuya')
  const records = result.logs.flatMap((entry, index) => {
    const rawTime = Number(entry.update_time)
    const time = rawTime >= 100000000000 ? Math.floor(rawTime / 1000) : rawTime
    if (!Number.isSafeInteger(time) || time <= 0) throw new Error('Invalid unlock event time from Tuya')
    const statuses = Array.isArray(entry.status) ? entry.status : entry.status ? [entry.status] : []
    return statuses.map((status, statusIndex) => {
      const method = typeof status.code === 'string' && /^unlock_[a-z_]{1,40}$/.test(status.code) ? status.code : 'unknown'
      const value = typeof status.value === 'string' ? status.value : Number.isSafeInteger(status.value) ? String(status.value) : ''
      return { id: `${time}-${index}-${statusIndex}`, time, method, passwordId: method === 'unlock_temporary' && /^\d{1,40}$/.test(value) ? value : null }
    })
  })
  return { records, total: result.total }
}

module.exports = { canonicalTuyaPath, signRequest, encryptPin, normalizePasswords, normalizeOfflinePasswords, normalizeUnlockLogs }