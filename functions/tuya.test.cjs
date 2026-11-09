const { normalizeUnlockLogs } = require('./tuya.cjs')

require('node:test').test('unlock history normalizes seconds and milliseconds without exposing raw credentials', () => {
  const assert = require('node:assert/strict')
  const result = normalizeUnlockLogs({ total: 2, logs: [
    { update_time: 1794135600000, status: { code: 'unlock_temporary', value: 12345 }, nick_name: 'private', media_key: 'secret' },
    { update_time: 1794135601, status: [{ code: 'unlock_offline_pd', value: 'secret-offline-code' }, { code: 'unlock_password', value: '7654321' }] },
  ] })
  assert.equal(result.records[0].time, 1794135600)
  assert.equal(result.records[0].passwordId, '12345')
  assert.equal(result.records[1].time, 1794135601)
  assert.equal(result.records[1].passwordId, null)
  assert.equal(result.records[2].passwordId, null)
  assert.ok(!JSON.stringify(result).includes('secret'))
  assert.ok(!JSON.stringify(result).includes('7654321'))
  assert.throws(() => normalizeUnlockLogs({ total: 1, logs: [{ update_time: 'invalid' }] }))
  assert.throws(() => normalizeUnlockLogs({ total: 0 }))
})
const { test } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { signRequest, encryptPin, normalizePasswords } = require('./tuya.cjs')

test('signs the documented Tuya service request', () => {
  const signature = signRequest({ clientId: 'client', secret: 'secret', token: 'token', timestamp: '123', method: 'GET', path: '/test' })
  const hash = crypto.createHash('sha256').update('').digest('hex')
  const expected = crypto.createHmac('sha256', 'secret').update(`clienttoken123GET\n${hash}\n\n/test`).digest('hex').toUpperCase()
  assert.equal(signature, expected)
})

test('decrypts the ticket and encrypts the seven-digit PIN', () => {
  const secret = '0123456789abcdef0123456789abcdef'
  const ticket = 'abcdefghijklmnop'
  const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(secret), null)
  const encryptedTicket = Buffer.concat([cipher.update(ticket), cipher.final()]).toString('hex')
  const encrypted = encryptPin('0123456', encryptedTicket, secret)
  const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(ticket), null)
  assert.equal(Buffer.concat([decipher.update(Buffer.from(encrypted, 'hex')), decipher.final()]).toString(), '0123456')
})

test('normalizes Tuya password metadata without exposing PINs', () => {
  const records = normalizePasswords([{ password_id: 1001, name: ' Guest ', effective_time: 1700000000, invalid_time: 1700003600, phase: 2, password: '1234567' }])
  assert.deepEqual(records, [{ passwordId: '1001', name: 'Guest', start: 1700000000, end: 1700003600, state: 'delivered' }])
  assert.equal(normalizePasswords([{ id: '42', effective_time: '1700000000', invalid_time: '1700003600', phase: 9 }])[0].state, 'unknown')
})

test('rejects malformed or unsafe Tuya password metadata', () => {
  assert.throws(() => normalizePasswords({ records: [] }))
  assert.throws(() => normalizePasswords([{ password_id: Number.MAX_SAFE_INTEGER + 1, effective_time: 1, invalid_time: 2 }]))
  assert.throws(() => normalizePasswords([{ password_id: 1, effective_time: null, invalid_time: 2 }]))
})