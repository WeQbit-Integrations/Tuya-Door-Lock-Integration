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
  const clearAllRequestId = crypto.randomUUID()
  const clearAllRef = getFirestore().collection('offlineClearOperations').doc(clearAllRequestId)
  const legacyOneTimeId = crypto.randomUUID()
  const legacyOneTimeRef = getFirestore().collection('oneTimeAccess').doc(legacyOneTimeId)
  const offlineId = crypto.randomUUID()
  const offlineRef = getFirestore().collection('offlineAccess').doc(offlineId)
  const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(process.env.TUYA_CLIENT_SECRET), null)
  const ticketKey = Buffer.concat([cipher.update('abcdefghijklmnop'), cipher.final()]).toString('hex')
  const now = Math.floor(Date.now() / 1000)
  const realFetch = global.fetch
  let testUserToken
  let clearOneRequests = 0
  let failClearOne = true
  let clearAllRequests = 0

  context.mock.method(global, 'fetch', async (url, options) => {
    if (!url.startsWith(process.env.TUYA_ENDPOINT)) return realFetch(url, options)
    if (url.includes('/v1.0/token?')) return new Response(JSON.stringify({ success: true, result: { access_token: 'test-token' } }))
    if (url.endsWith('/password-ticket')) return new Response(JSON.stringify({ success: true, result: { ticket_id: 'ticket', ticket_key: ticketKey } }))
    if (url.includes('/door-lock/open-logs?')) {
      const params = new URL(url).searchParams
      assert.equal(params.get('page_no'), '1')
      assert.equal(params.get('page_size'), '50')
      assert.equal(params.get('start_time'), String((now - 86400) * 1000))
      assert.equal(params.get('end_time'), String(now * 1000))
      return new Response(JSON.stringify({ success: true, result: { total: 51, logs: [{ update_time: now * 1000, status: { code: 'unlock_temporary', value: '12345' } }] } }))
    }
    if (url.includes('/door-lock/offline-temp-password?')) {
      const requestUrl = new URL(url)
      const page = requestUrl.searchParams.get('pageNo')
      assert.equal(requestUrl.search, `?pageNo=${page}&pageSize=100&pwdTypeCodes=once&targetStatus=`)
      return new Response(JSON.stringify({ success: true, result: { total: 101, has_more: page === '1', records: [{ pwd_id: page === '1' ? '67891' : '67892', pwd_name: page === '1' ? 'One-time visitor' : 'Second page visitor', pwd_type_code: 'once', gmt_create: now, gmt_start: now, gmt_expired: now + 21600, status: 1, password: 'must-not-be-returned' }] } }))
    }
    if (url.endsWith('/offline-temp-password')) {
      const body = JSON.parse(options.body)
      if (body.type === 'clear_one') {
        clearOneRequests += 1
        assert.deepEqual(body, { type: 'clear_one', password_id: '67891' })
        if (failClearOne) return new Response(JSON.stringify({ success: false, code: 500, msg: 'Mock purge failure' }))
        return new Response(JSON.stringify({ success: true, result: true }))
      }
      if (body.type === 'clear_all') {
        clearAllRequests += 1
        assert.deepEqual(body, { type: 'clear_all' })
        return new Response(JSON.stringify({ success: true, result: true }))
      }
      if (body.type === 'multiple') {
        assert.deepEqual(body, { type: 'multiple', name: 'Offline visitor', effective_time: now + 60, invalid_time: now + 7260 })
        return new Response(JSON.stringify({ success: true, result: { offline_temp_password_id: '67890', offline_temp_password: '9876543210', effective_time: now, invalid_time: now + 7200 } }))
      }
      assert.deepEqual(body, { type: 'once', name: 'One-time visitor' })
      return new Response(JSON.stringify({ success: true, result: { offline_temp_password_id: '67891', offline_temp_password: '0123456789', effective_time: now, invalid_time: now + 21600 } }))
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
    const logsRequest = { action: 'logs', start: now - 86400, end: now, page: 1 }
    await assert.rejects(manageAccess.run({ data: logsRequest }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data: logsRequest, auth: { uid: 'non-admin', token: {} } }), { code: 'permission-denied' })
    await assert.rejects(manageAccess.run({ data: { ...logsRequest, start: now - 91 * 86400 }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'invalid-argument' })
    await assert.rejects(manageAccess.run({ data: { ...logsRequest, page: 0 }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'invalid-argument' })
    const logs = await manageAccess.run({ data: logsRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.equal(logs.records[0].passwordId, '12345')
    assert.equal(logs.records[0].time, now)
    assert.equal(logs.hasMore, true)
    const cloudListRequest = { action: 'list-tuya-one-time', page: 1 }
    await assert.rejects(manageAccess.run({ data: cloudListRequest }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data: cloudListRequest, auth: { uid: 'non-admin', token: {} } }), { code: 'permission-denied' })
    const cloudList = await manageAccess.run({ data: cloudListRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.equal(cloudList.total, 101)
    assert.equal(cloudList.hasMore, true)
    assert.equal(cloudList.records[0].name, 'One-time visitor')
    assert.equal(cloudList.records[0].state, 'generated')
    assert.equal(cloudList.records[0].passwordId, '67891')
    assert.ok(!JSON.stringify(cloudList).includes('must-not-be-returned'))
    const cloudListPageTwo = await manageAccess.run({ data: { ...cloudListRequest, page: 2 }, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.equal(cloudListPageTwo.hasMore, false)
    assert.equal(cloudListPageTwo.records[0].name, 'Second page visitor')
    const oneTimeRequest = { action: 'create-one-time', requestId: oneTimeId, name: 'One-time visitor' }
    await assert.rejects(manageAccess.run({ data: oneTimeRequest }), { code: 'unauthenticated' })
    const oneTime = await manageAccess.run({ data: oneTimeRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.equal(oneTime.pin, '0123456789')
    assert.equal(oneTime.stored, true)
    assert.equal((await oneTimeRef.get()).data().pin, '0123456789')
    assert.equal((await oneTimeRef.get()).data().passwordId, '67891')
    await assert.rejects(manageAccess.run({ data: oneTimeRequest, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'already-exists' })
    await legacyOneTimeRef.create({ name: 'Legacy one-time record', state: 'generated' })
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: legacyOneTimeId }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'failed-precondition' })
    assert.equal(clearOneRequests, 0)
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: oneTimeId } }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: oneTimeId }, auth: { uid: 'non-admin', token: {} } }), { code: 'permission-denied' })
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: offlineId }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'not-found' })
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: oneTimeId }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'unavailable' })
    assert.equal((await oneTimeRef.get()).data().purgeState, 'unknown')
    failClearOne = false
    assert.deepEqual(await manageAccess.run({ data: { action: 'purge-one-time', id: oneTimeId }, auth: { uid: 'test-admin', token: { admin: true } } }), { state: 'purge-submitted' })
    assert.equal((await oneTimeRef.get()).data().purgeState, 'submitted')
    assert.equal((await oneTimeRef.get()).data().state, 'purge-submitted')
    assert.equal(clearOneRequests, 2)
    await assert.rejects(manageAccess.run({ data: { action: 'purge-one-time', id: oneTimeId }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'failed-precondition' })
    assert.equal(clearOneRequests, 2)
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
    assert.equal(savedOffline.passwordId, '67890')
    await assert.rejects(manageAccess.run({ data: offlineRequest, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'already-exists' })
    const clearAllRequest = { action: 'purge-all-offline', requestId: clearAllRequestId, confirmation: 'CLEAR ALL OFFLINE PASSWORDS' }
    await assert.rejects(manageAccess.run({ data: clearAllRequest }), { code: 'unauthenticated' })
    await assert.rejects(manageAccess.run({ data: clearAllRequest, auth: { uid: 'non-admin', token: {} } }), { code: 'permission-denied' })
    await assert.rejects(manageAccess.run({ data: { ...clearAllRequest, confirmation: 'clear all' }, auth: { uid: 'test-admin', token: { admin: true } } }), { code: 'invalid-argument' })
    assert.equal(clearAllRequests, 0)
    const cleared = await manageAccess.run({ data: clearAllRequest, auth: { uid: 'test-admin', token: { admin: true } } })
    assert.deepEqual(cleared, { state: 'purge-submitted', updatedRecords: 1 })
    assert.equal(clearAllRequests, 1)
    assert.equal((await clearAllRef.get()).data().state, 'submitted')
    assert.equal((await oneTimeRef.get()).data().purgeState, 'submitted')
    assert.equal((await offlineRef.get()).data().state, 'purge-submitted')
    assert.equal((await ref.get()).data().state, 'pending')
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
    await clearAllRef.delete()
    await legacyOneTimeRef.delete()
    await offlineRef.delete()
  }
})