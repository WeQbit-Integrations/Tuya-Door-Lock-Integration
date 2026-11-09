const crypto = require('node:crypto')

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

module.exports = { signRequest, encryptPin, normalizePasswords, normalizeUnlockLogs }