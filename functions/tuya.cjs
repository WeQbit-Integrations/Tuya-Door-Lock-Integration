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

module.exports = { signRequest, encryptPin, normalizePasswords }