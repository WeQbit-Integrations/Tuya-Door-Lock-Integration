const { initializeApp } = require('firebase-admin/app')
const { getFirestore, FieldValue } = require('firebase-admin/firestore')
const { onCall, HttpsError } = require('firebase-functions/v2/https')
const { defineSecret, defineString } = require('firebase-functions/params')
const { signRequest, encryptPin, normalizePasswords } = require('./tuya.cjs')

initializeApp()
const db = getFirestore()
const tuyaSecret = defineSecret('TUYA_CLIENT_SECRET')
const tuyaClientId = defineString('TUYA_CLIENT_ID')
const tuyaDeviceId = defineString('TUYA_DEVICE_ID')
const tuyaEndpoint = defineString('TUYA_ENDPOINT')
const allowedEndpoints = ['https://openapi.tuyaus.com', 'https://openapi.tuyaeu.com', 'https://openapi.tuyacn.com', 'https://openapi.tuyain.com', 'https://openapi-sg.iotbing.com', 'https://openapi-ueaz.tuyaus.com', 'https://openapi-weaz.tuyaeu.com']

async function tuyaRequest(method, path, body, token = '') {
  const endpoint = tuyaEndpoint.value()
  if (!allowedEndpoints.includes(endpoint)) throw new Error('Unsupported Tuya API endpoint')
  const payload = body === undefined ? '' : JSON.stringify(body)
  const timestamp = Date.now().toString()
  const clientId = tuyaClientId.value()
  const headers = { client_id: clientId, t: timestamp, sign_method: 'HMAC-SHA256', sign: signRequest({ clientId, secret: tuyaSecret.value(), token, timestamp, method, path, body: payload }) }
  if (token) headers.access_token = token
  if (payload) headers['Content-Type'] = 'application/json'
  const response = await fetch(endpoint + path, { method, headers, ...(payload ? { body: payload } : {}), signal: AbortSignal.timeout(15000) })
  const result = await response.json()
  if (!response.ok || !result.success) throw new Error(`Tuya request failed (${result.code || response.status}): ${result.msg || 'Unknown error'}`)
  return result.result
}

async function accessToken() {
  const result = await tuyaRequest('GET', '/v1.0/token?grant_type=1')
  if (!result?.access_token) throw new Error('Tuya did not return an access token')
  return result.access_token
}

function validateCreate(data) {
  const name = typeof data.name === 'string' ? data.name.trim() : ''
  if (!name || name.length > 80 || typeof data.pin !== 'string' || !/^\d{7}$/.test(data.pin)) throw new HttpsError('invalid-argument', 'Enter a visitor name and a seven-digit PIN.')
  if (!Number.isSafeInteger(data.start) || !Number.isSafeInteger(data.end) || data.end <= data.start || data.end <= Math.floor(Date.now() / 1000)) throw new HttpsError('invalid-argument', 'Select a valid start and future expiration time.')
  if (typeof data.requestId !== 'string' || !/^[a-f0-9-]{36}$/i.test(data.requestId)) throw new HttpsError('invalid-argument', 'Invalid request ID.')
  return name
}

exports.manageAccess = onCall({ secrets: [tuyaSecret], timeoutSeconds: 60 }, async (request) => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in to continue.')
  if (request.auth.token.admin !== true) throw new HttpsError('permission-denied', 'An administrator account is required.')
  const data = request.data || {}
  const deviceId = tuyaDeviceId.value()
  if (tuyaClientId.value() === 'local-unconfigured' || deviceId === 'local-unconfigured') throw new HttpsError('failed-precondition', 'Tuya is not configured. Set the client ID, lock device ID, and data-center endpoint before continuing.')
  if (!/^[a-zA-Z0-9_-]+$/.test(deviceId)) throw new HttpsError('failed-precondition', 'Invalid configured device ID.')
  const base = `/v1.0/devices/${deviceId}/door-lock`

  if (data.action === 'list') {
    try {
      const token = await accessToken()
      const result = await tuyaRequest('GET', `${base}/temp-passwords?valid=true`, undefined, token)
      return { records: normalizePasswords(result) }
    } catch (error) {
      throw new HttpsError('unavailable', `Could not load temporary passwords from Tuya. ${error.message}`)
    }
  }

  if (data.action === 'create-one-time') {
    const name = typeof data.name === 'string' ? data.name.trim() : ''
    if (!name || name.length > 80 || typeof data.requestId !== 'string' || !/^[a-f0-9-]{36}$/i.test(data.requestId)) throw new HttpsError('invalid-argument', 'Enter a visitor name and a valid request ID.')
    const ref = db.collection('oneTimeAccess').doc(data.requestId)
    try {
      await ref.create({ name, state: 'submitting', createdBy: request.auth.uid, createdAt: FieldValue.serverTimestamp() })
    } catch (error) {
      if (error.code === 6 || error.code === 'already-exists') throw new HttpsError('already-exists', 'This request was already submitted. Check the one-time password list before retrying.')
      throw new HttpsError('unavailable', 'Could not save the request. No password was requested.')
    }
    let submitted = false
    let generated
    try {
      const token = await accessToken()
      submitted = true
      const result = await tuyaRequest('POST', `/v1.1/devices/${deviceId}/door-lock/offline-temp-password`, { type: 'once', name }, token)
      const start = Number(result?.effective_time)
      const end = Number(result?.invalid_time)
      if (typeof result?.offline_temp_password !== 'string' || !/^\d{4,20}$/.test(result.offline_temp_password) || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start <= 0 || end <= start) throw new Error('Tuya returned invalid one-time password data')
      generated = { pin: result.offline_temp_password, start, end }
      await ref.update({ ...generated, state: 'generated', updatedAt: FieldValue.serverTimestamp() })
      return { id: data.requestId, ...generated, stored: true }
    } catch (error) {
      await ref.update({ state: submitted ? 'unknown' : 'failed', updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      if (generated) return { id: data.requestId, ...generated, stored: false }
      throw new HttpsError('unavailable', submitted ? 'The one-time password request could not be confirmed. Check Tuya before retrying.' : `No password was requested. ${error.message}`)
    }
  }

  if (data.action === 'create') {
    const name = validateCreate(data)
    const ref = db.collection('visitorAccess').doc(data.requestId)
    try {
      await ref.create({ name, pin: data.pin, start: data.start, end: data.end, state: 'submitting', createdBy: request.auth.uid, createdAt: FieldValue.serverTimestamp() })
    } catch (error) {
      if (error.code === 6 || error.code === 'already-exists') throw new HttpsError('already-exists', 'This request was already submitted. Check the visitor list and Tuya app before retrying.')
      throw new HttpsError('unavailable', 'Could not save the request. No PIN was submitted.')
    }
    let submitted = false
    try {
      const token = await accessToken()
      const ticket = await tuyaRequest('POST', `${base}/password-ticket`, undefined, token)
      const password = encryptPin(data.pin, ticket.ticket_key, tuyaSecret.value())
      submitted = true
      const result = await tuyaRequest('POST', `${base}/temp-password`, { name, password, password_type: 'ticket', ticket_id: ticket.ticket_id, effective_time: data.start, invalid_time: data.end, type: 0 }, token)
      if (result?.id === undefined || result?.id === null) throw new Error('Tuya did not return a password ID')
      await ref.update({ passwordId: String(result.id), state: 'pending', updatedAt: FieldValue.serverTimestamp() })
      return { id: data.requestId, state: 'pending' }
    } catch (error) {
      await ref.update({ state: submitted ? 'unknown' : 'failed', updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      throw new HttpsError('unavailable', submitted ? 'Submission could not be confirmed. Check the Tuya app before retrying; the PIN may exist.' : `PIN was not submitted. ${error.message}`)
    }
  }

  if (!['check', 'revoke'].includes(data.action) || typeof data.id !== 'string' || !/^[a-f0-9-]{36}$/i.test(data.id)) throw new HttpsError('invalid-argument', 'Invalid action or visitor.')
  const ref = db.collection('visitorAccess').doc(data.id)
  const snapshot = await ref.get()
  if (!snapshot.exists || !snapshot.data().passwordId) throw new HttpsError('not-found', 'No Tuya password ID is available for this visitor.')
  const passwordId = encodeURIComponent(snapshot.data().passwordId)
  try {
    const token = await accessToken()
    if (data.action === 'check') {
      const result = await tuyaRequest('GET', `${base}/temp-password/${passwordId}`, undefined, token)
      const state = ({ 0: 'revoked', 1: 'pending', 2: 'delivered', 3: 'revoking' })[result.phase] || 'unknown'
      await ref.update({ state, updatedAt: FieldValue.serverTimestamp() })
      return { state }
    }
    await tuyaRequest('DELETE', `${base}/temp-passwords/${passwordId}`, undefined, token)
    await ref.update({ state: 'revoking', updatedAt: FieldValue.serverTimestamp() })
    return { state: 'revoking' }
  } catch (error) {
    throw new HttpsError('unavailable', `Could not ${data.action} access. Check the Tuya app before retrying. ${error.message}`)
  }
})