const { initializeApp, applicationDefault } = require('firebase-admin/app')
const { getAuth } = require('firebase-admin/auth')

const email = process.argv[2]
if (!email || !process.env.GOOGLE_CLOUD_PROJECT) {
  console.error('Set GOOGLE_CLOUD_PROJECT and provide an existing Firebase user email.')
  process.exit(1)
}
initializeApp({ credential: applicationDefault(), projectId: process.env.GOOGLE_CLOUD_PROJECT })
getAuth().getUserByEmail(email).then(async (user) => {
  await getAuth().setCustomUserClaims(user.uid, { ...user.customClaims, admin: true })
  console.log('Admin claim granted. Sign out and sign in again.')
}).catch((error) => { console.error(error.message); process.exitCode = 1 })