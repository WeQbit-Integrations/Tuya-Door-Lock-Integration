const { test } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

test('stores a seven-digit PIN in Firestore without changing the lock', { skip: process.env.RUN_FIREBASE_EMULATOR_TESTS !== '1' }, async (context) => {
  process.env.FIRESTORE_EMULATOR_HOST = '127.0.0.1:8080'
  process.env.GCLOUD_PROJECT = 'demo-entrydesk'
  process.env.TUYA_CLIENT_ID = 'test-client'
  process.env.TUYA_DEVICE_ID = 'test-device'
  process.env.TUYA_ENDPOINT = 'https://openapi.tuyaeu.com'
  process.env.TUYA_CLIENT_SECRET = '0123456789abcdef0123456789abcdef'

  const { manageAccess } = require('./index.cjs')
  const { getFirestore } = require('firebase-admin/firestore')
  const requestId = crypto.randomUUID()
  const ref = getFirestore().collection('visitorAccess').doc(requestId)
  const oneTimeId = crypto.randomUUID()
  const oneTimeRef = getFirestore().collection('oneTimeAccess').doc(oneTimeId)
  const offlineId = crypto.randomUUID()
  const offlineRef = getFirestore().collection('offlineAccess').doc(offlineId)
  const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(process.env.TUYA_CLIENT_SECRET), null)
  const ticketKey = Buffer.concat([cipher.update('abcdefghijklmnop'), cipher.final()]).toString('hex')
  const now = Math.floor(Date.now() / 1000)
  const realFetch = global.fetch
  let testUserToken

  context.mock.method(global, 'fetch', async (url, options) => {
    if (!url.startsWith(process.env.TUYA_ENDPOINT)) return realFetch(url, options)
    if (url.includes('/v1.0/token?')) return new Response(JSON.stringify({ success: true, result: { access_token: 'test-token' } }))
    if (url.endsWith('/password-ticket')) return new Response(JSON.stringify({ success: true, result: { ticket_id: 'ticket', ticket_key: ticketKey } }))
    if (url.endsWith('/offline-temp-password')) {
      const body = JSON.parse(options.body)
      if (body.type === 'multiple') {
        assert.deepEqual(body, { type: 'multiple', name: 'Offline visitor', effective_time: now + 60, invalid_time: now + 7260 })
        return new Response(JSON.stringify({ success: true, result: { offline_temp_password: '9876543210', effective_time: now, invalid_time: now + 7200 } }))
      }
      assert.deepEqual(body, { type: 'once', name: 'One-time visitor' })
      return new Response(JSON.stringify({ success: true, result: { offline_temp_password: '0123456789', effective_time: now, invalid_time: now + 21600 } }))
    }
    if (url.endsWith('/temp-password')) {
      assert.notEqual(JSON.parse(options.body).password, '0123456')
      return new Response(JSON.stringify({ success: true, result: { id: 12345 } }))
    }
    throw new Error('Unexpected Tuya request')
  })

  try {
    const data = { action: 'create', requestId, name: 'Local storage test', pin: '0123456', start: now, end: now + 3600 }
    await assert.rejects(manageAccess.run({ data }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data, auth: { uid: 'non-admin', token: {} } }), { code: 'permission-denied' })
    await assert.rejects(manageAccess.run({ data: { ...data, pin: 1234567 }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'invalid-argument' })
    await manageAccess.run({ data, auth: { uid: 'test-admin', token: { admin: true } } })
    const saved = (await ref.get()).data()
    assert.equal(saved.pin, '0123456')
    assert.equal(saved.passwordId, '12345')
    assert.equal(saved.state, 'pending')
    const oneTimeRequest = { action: 'create-one-time', requestId: oneTimeId, name: 'One-time visitor' }
    await assert.rejects(manageAccess.run({ data: oneTimeRequest }), { code: 'unauthenticated' })
    const oneTime = await manageAccess.run({ data: oneTimeRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.equal(oneTime.pin, '0123456789')
    assert.equal(oneTime.stored, true)
    assert.equal((await oneTimeRef.get()).data().pin, '0123456789')
    await assert.rejects(manageAccess.run({ data: oneTimeRequest, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'already-exists' })
    const offlineRequest = { action: 'create-offline', requestId: offlineId, name: 'Offline visitor', start: now + 60, end: now + 7260 }
    await assert.rejects(manageAccess.run({ data: offlineRequest }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data: { ...offlineRequest, end: offlineRequest.start }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'invalid-argument' })
    const offline = await manageAccess.run({ data: offlineRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.deepEqual({ pin: offline.pin, start: offline.start, end: offline.end, stored: offline.stored }, { pin: '9876543210', start: now, end: now + 7200, stored: true })
    const savedOffline = (await offlineRef.get()).data()
    assert.equal(savedOffline.requestedStart, offlineRequest.start)
    assert.equal(savedOffline.requestedEnd, offlineRequest.end)
    assert.equal(savedOffline.start, now)
    assert.equal(savedOffline.pin, '9876543210')
    await assert.rejects(manageAccess.run({ data: offlineRequest, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'already-exists' })
    const documentUrl = `http://127.0.0.1:8080/v1/projects/demo-entrydesk/databases/(default)/documents/visitorAccess/${requestId}`
    const response = await realFetch(documentUrl)
    assert.equal(response.status, 403)
    const oneTimeDocumentUrl = `http://127.0.0.1:8080/v1/projects/demo-entrydesk/databases/(default)/documents/oneTimeAccess/${oneTimeId}`
    assert.equal((await realFetch(oneTimeDocumentUrl)).status, 403)
    const offlineDocumentUrl = `http://127.0.0.1:8080/v1/projects/demo-entrydesk/databases/(default)/documents/offlineAccess/${offlineId}`
    assert.equal((await realFetch(offlineDocumentUrl)).status, 403)
    const signup = await realFetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=local-demo-key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${requestId}@example.test`, password: 'local-test-only', returnSecureToken: true }),
    })
    assert.equal(signup.status, 200)
    testUserToken = (await signup.json()).idToken
    const nonAdminResponse = await realFetch(documentUrl, { headers: { Authorization: `Bearer ${testUserToken}` } })
    assert.equal(nonAdminResponse.status, 403)
    assert.equal((await realFetch(oneTimeDocumentUrl, { headers: { Authorization: `Bearer ${testUserToken}` } })).status, 403)
    assert.equal((await realFetch(offlineDocumentUrl, { headers: { Authorization: `Bearer ${testUserToken}` } })).status, 403)
  } finally {
    if (testUserToken) {
      await realFetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:delete?key=local-demo-key', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: testUserToken }),
      })
    }
    await ref.delete()
    await oneTimeRef.delete()
    await offlineRef.delete()
  }
})