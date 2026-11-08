const { initializeApp } = require('firebase-admin/app')
const { getAuth } = require('firebase-admin/auth')

process.env.FIREBASE_AUTH_EMULATOR_HOST = '127.0.0.1:9099'
initializeApp({ projectId: 'demo-entrydesk' })

async function main() {
  const auth = getAuth()
  const email = 'admin@entrydesk.local'
  let user
  try {
    user = await auth.getUserByEmail(email)
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error
    user = await auth.createUser({ email, password: 'local-demo-only' })
  }
  await auth.setCustomUserClaims(user.uid, { ...user.customClaims, admin: true })
  console.log('Local emulator administrator is ready: admin@entrydesk.local')
}

main().catch((error) => { console.error(error.message); process.exitCode = 1 })