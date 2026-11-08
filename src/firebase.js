import { initializeApp } from 'firebase/app'
import { getAuth, connectAuthEmulator, signInWithEmailAndPassword } from 'firebase/auth'
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore'
import { getFunctions, connectFunctionsEmulator } from 'firebase/functions'

export const useEmulators = import.meta.env.MODE === 'emulator'
const config = useEmulators
	? { apiKey: 'local-demo-key', authDomain: 'demo-entrydesk.firebaseapp.com', projectId: 'demo-entrydesk', appId: 'local-demo-app' }
	: { apiKey: import.meta.env.VITE_FIREBASE_API_KEY, authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN, projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID, appId: import.meta.env.VITE_FIREBASE_APP_ID }
export const configured = Object.values(config).every(Boolean)
const app = configured ? initializeApp(config) : null
export const auth = app ? getAuth(app) : null
export const db = app ? getFirestore(app) : null
export const functions = app ? getFunctions(app, import.meta.env.VITE_FIREBASE_FUNCTIONS_REGION || 'us-central1') : null

if (useEmulators) {
	connectAuthEmulator(auth, 'http://127.0.0.1:9099', { disableWarnings: true })
	connectFirestoreEmulator(db, '127.0.0.1', 8080)
	connectFunctionsEmulator(functions, '127.0.0.1', 5001)
}

let localSignIn
export function signInAsLocalAdmin() {
	if (!useEmulators) throw new Error('Local sign-in is only available with Firebase emulators.')
	if (!localSignIn) localSignIn = signInWithEmailAndPassword(auth, 'admin@entrydesk.local', 'local-demo-only').finally(() => { localSignIn = null })
	return localSignIn
}