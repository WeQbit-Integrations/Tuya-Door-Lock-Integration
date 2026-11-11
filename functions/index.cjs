const { initializeApp } = require('firebase-admin/app')
const { getFirestore, FieldValue } = require('firebase-admin/firestore')
const { onCall, HttpsError } = require('firebase-functions/v2/https')
const { defineSecret, defineString } = require('firebase-functions/params')
const { canonicalTuyaPath, signRequest, encryptPin, normalizePasswords, normalizeOfflinePasswords, normalizeUnlockLogs } = require('./tuya.cjs')

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
  const requestPath = canonicalTuyaPath(path)
  const timestamp = Date.now().toString()
  const clientId = tuyaClientId.value()
  const headers = { client_id: clientId, t: timestamp, sign_method: 'HMAC-SHA256', sign: signRequest({ clientId, secret: tuyaSecret.value(), token, timestamp, method, path: requestPath, body: payload }) }
  if (token) headers.access_token = token
  if (payload) headers['Content-Type'] = 'application/json'
  const response = await fetch(endpoint + requestPath, { method, headers, ...(payload ? { body: payload } : {}), signal: AbortSignal.timeout(15000) })
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

  if (data.action === 'logs') {
    const page = data.page ?? 1
    if (!Number.isSafeInteger(data.start) || !Number.isSafeInteger(data.end) || data.start <= 0 || data.end <= data.start || data.end > Math.floor(Date.now() / 1000) + 60 || data.end - data.start > 90 * 86400 || !Number.isSafeInteger(page) || page < 1 || page > 1000) throw new HttpsError('invalid-argument', 'Select a past date range of up to 90 days and a valid page.')
    try {
      const token = await accessToken()
      const path = `/v1.1/devices/${deviceId}/door-lock/open-logs?page_no=${page}&page_size=50&start_time=${data.start * 1000}&end_time=${data.end * 1000}`
      const result = normalizeUnlockLogs(await tuyaRequest('GET', path, undefined, token))
      return { ...result, page, hasMore: page * 50 < result.total }
    } catch (error) {
      throw new HttpsError('unavailable', `Could not load unlock history from Tuya. ${error.message}`)
    }
  }

  if (data.action === 'list') {
    try {
      const token = await accessToken()
      const result = await tuyaRequest('GET', `${base}/temp-passwords?valid=true`, undefined, token)
      return { records: normalizePasswords(result) }
    } catch (error) {
      throw new HttpsError('unavailable', `Could not load temporary passwords from Tuya. ${error.message}`)
    }
  }

  if (data.action === 'list-tuya-one-time') {
    const page = data.page ?? 1
    if (!Number.isSafeInteger(page) || page < 1 || page > 1000) throw new HttpsError('invalid-argument', 'Invalid offline password page.')
    try {
      const token = await accessToken()
      const path = `/v1.0/devices/${deviceId}/door-lock/offline-temp-password?pageNo=${page}&pageSize=100&pwdTypeCodes=once&targetStatus=`
      const result = normalizeOfflinePasswords(await tuyaRequest('GET', path, undefined, token), page)
      return { ...result, page }
    } catch (error) {
      throw new HttpsError('unavailable', `Could not load one-time passwords from Tuya. ${error.message}`)
    }
  }

  if (data.action === 'purge-one-time') {
    if (typeof data.id !== 'string' || !/^[a-f0-9-]{36}$/i.test(data.id)) throw new HttpsError('invalid-argument', 'Invalid one-time password.')
    const ref = db.collection('oneTimeAccess').doc(data.id)
    let passwordId
    try {
      await db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(ref)
        if (!snapshot.exists) throw new HttpsError('not-found', 'One-time password not found.')
        const saved = snapshot.data()
        if (saved.state === 'purge-submitted') throw new HttpsError('failed-precondition', 'A purge request was already accepted by Tuya for this password.')
        if (saved.state !== 'generated' || !/^\d{1,40}$/.test(String(saved.passwordId || ''))) throw new HttpsError('failed-precondition', 'This password has no confirmed Tuya ID and cannot be purged here.')
        if (saved.purgeState === 'pending') throw new HttpsError('aborted', 'A purge request is already in progress.')
        passwordId = String(saved.passwordId)
        transaction.update(ref, { purgeState: 'pending', updatedAt: FieldValue.serverTimestamp() })
      })
    } catch (error) {
      if (error instanceof HttpsError) throw error
      throw new HttpsError('unavailable', 'Could not reserve this password for purging. No Tuya request was sent.')
    }

    try {
      const token = await accessToken()
      await tuyaRequest('POST', `/v1.1/devices/${deviceId}/door-lock/offline-temp-password`, { type: 'clear_one', password_id: passwordId }, token)
      await ref.update({ state: 'purge-submitted', purgeState: 'submitted', purgeRequestedAt: FieldValue.serverTimestamp(), updatedAt: FieldValue.serverTimestamp() })
      return { state: 'purge-submitted' }
    } catch (error) {
      await ref.update({ purgeState: 'unknown', updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      throw new HttpsError('unavailable', `Tuya did not confirm the purge. Check the Tuya app before retrying. ${error.message}`)
    }
  }

  if (data.action === 'purge-all-offline') {
    const requestId = data.requestId
    if (data.confirmation !== 'CLEAR ALL OFFLINE PASSWORDS' || typeof requestId !== 'string' || !/^[a-f0-9-]{36}$/i.test(requestId)) throw new HttpsError('invalid-argument', 'Type CLEAR ALL OFFLINE PASSWORDS in the confirmation prompt.')
    const auditRef = db.collection('offlineClearOperations').doc(requestId)
    try {
      await auditRef.create({ state: 'submitting', createdBy: request.auth.uid, createdAt: FieldValue.serverTimestamp() })
    } catch (error) {
      if (error.code === 6 || error.code === 'already-exists') throw new HttpsError('already-exists', 'This clear-all request was already submitted.')
      throw new HttpsError('unavailable', 'Could not save the clear-all audit record. No Tuya request was sent.')
    }

    try {
      const token = await accessToken()
      await tuyaRequest('POST', `/v1.1/devices/${deviceId}/door-lock/offline-temp-password`, { type: 'clear_all' }, token)
    } catch (error) {
      await auditRef.update({ state: 'unknown', updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      throw new HttpsError('unavailable', `Tuya did not confirm clearing offline passwords. Check Tuya before retrying. ${error.message}`)
    }

    let updatedRecords = 0
    try {
      for (const collectionName of ['oneTimeAccess', 'offlineAccess']) {
        const snapshot = await db.collection(collectionName).get()
        const records = snapshot.docs.filter((document) => /^\d{1,40}$/.test(String(document.data().passwordId || '')) && document.data().state !== 'purge-submitted')
        for (let offset = 0; offset < records.length; offset += 450) {
          const batch = db.batch()
          for (const document of records.slice(offset, offset + 450)) batch.update(document.ref, { state: 'purge-submitted', purgeState: 'submitted', purgeRequestedAt: FieldValue.serverTimestamp(), updatedAt: FieldValue.serverTimestamp() })
          await batch.commit()
          updatedRecords += records.slice(offset, offset + 450).length
        }
      }
      await auditRef.update({ state: 'submitted', updatedRecords, updatedAt: FieldValue.serverTimestamp() })
      return { state: 'purge-submitted', updatedRecords }
    } catch {
      await auditRef.update({ state: 'accepted-records-pending', updatedRecords, updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      throw new HttpsError('unavailable', 'Tuya accepted the clear-all request, but some website records could not be updated. Check Tuya before taking any further action.')
    }
  }

  if (data.action === 'create-one-time' || data.action === 'create-offline') {
    const multiple = data.action === 'create-offline'
    const name = typeof data.name === 'string' ? data.name.trim() : ''
    if (!name || name.length > 80 || typeof data.requestId !== 'string' || !/^[a-f0-9-]{36}$/i.test(data.requestId)) throw new HttpsError('invalid-argument', 'Enter a visitor name and a valid request ID.')
    if (multiple && (!Number.isSafeInteger(data.start) || !Number.isSafeInteger(data.end) || data.start <= 0 || data.end <= data.start || data.end <= Math.floor(Date.now() / 1000))) throw new HttpsError('invalid-argument', 'Select a valid start and future expiration time.')
    const ref = db.collection(multiple ? 'offlineAccess' : 'oneTimeAccess').doc(data.requestId)
    try {
      await ref.create({ name, ...(multiple ? { requestedStart: data.start, requestedEnd: data.end } : {}), state: 'submitting', createdBy: request.auth.uid, createdAt: FieldValue.serverTimestamp() })
    } catch (error) {
      if (error.code === 6 || error.code === 'already-exists') throw new HttpsError('already-exists', 'This request was already submitted. Check the password list before retrying.')
      throw new HttpsError('unavailable', 'Could not save the request. No password was requested.')
    }
    let submitted = false
    let generated
    try {
      const token = await accessToken()
      submitted = true
      const body = multiple ? { type: 'multiple', name, effective_time: data.start, invalid_time: data.end } : { type: 'once', name }
      const result = await tuyaRequest('POST', `/v1.1/devices/${deviceId}/door-lock/offline-temp-password`, body, token)
      const start = Number(result?.effective_time)
      const end = Number(result?.invalid_time)
      if (typeof result?.offline_temp_password !== 'string' || !/^\d{4,20}$/.test(result.offline_temp_password) || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start <= 0 || end <= start) throw new Error('Tuya returned invalid offline password data')
      const rawPasswordId = result.offline_temp_password_id
      const passwordId = typeof rawPasswordId === 'string' ? rawPasswordId : Number.isSafeInteger(rawPasswordId) ? String(rawPasswordId) : ''
      generated = { pin: result.offline_temp_password, start, end, ...(/^\d{1,40}$/.test(passwordId) ? { passwordId } : {}) }
      await ref.update({ ...generated, state: 'generated', updatedAt: FieldValue.serverTimestamp() })
      return { id: data.requestId, ...generated, stored: true }
    } catch (error) {
      await ref.update({ state: submitted ? 'unknown' : 'failed', updatedAt: FieldValue.serverTimestamp() }).catch(() => {})
      if (generated) return { id: data.requestId, ...generated, stored: false }
      throw new HttpsError('unavailable', submitted ? 'The offline password request could not be confirmed. Check Tuya before retrying.' : `No password was requested. ${error.message}`)
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