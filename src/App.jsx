import { useEffect, useState } from 'react'
import { onAuthStateChanged, signInWithEmailAndPassword, signOut } from 'firebase/auth'
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore'
import { httpsCallable } from 'firebase/functions'
import { ArrowDownUp, ArrowRight, Check, Clipboard, Clock3, DoorOpen, Eye, EyeOff, KeyRound, LogOut, RefreshCw, ShieldCheck, Trash2, Users, Wifi, X } from 'lucide-react'
import { auth, db, functions, configured, useEmulators, signInAsLocalAdmin } from './firebase'
import OneTimePasswords from './OneTimePasswords'
import './App.css'

const localInput = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
const formatDate = (seconds) => new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })
const freshForm = () => ({ name: '', start: localInput(new Date()), end: localInput(new Date(Date.now() + 86400000)) })
const labels = { submitting: 'Submitting', pending: 'Awaiting delivery', delivered: 'Sent to lock', revoking: 'Revocation pending', revoked: 'Tuya reports deleted', failed: 'Failed', unknown: 'Needs review' }

function randomPin() {
  const values = new Uint32Array(1)
  do { crypto.getRandomValues(values) } while (values[0] >= 4290000000)
  return String(values[0] % 10000000).padStart(7, '0')
}

function App() {
  const [view, setView] = useState('visitors')
  const [user, setUser] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [records, setRecords] = useState([])
  const [deviceRecords, setDeviceRecords] = useState([])
  const [syncing, setSyncing] = useState(false)
  const [loginOpen, setLoginOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [form, setForm] = useState(freshForm)
  const [pin, setPin] = useState('')
  const [shownPin, setShownPin] = useState(null)
  const [issued, setIssued] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [filter, setFilter] = useState('all')
  const [sortAscending, setSortAscending] = useState(true)
  const [copied, setCopied] = useState(false)
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 60000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!auth) return
    return onAuthStateChanged(auth, async (current) => {
      if (useEmulators && (!current || current.email !== 'admin@entrydesk.local')) {
        setUser(null); setIsAdmin(false); setRecords([]); setDeviceRecords([])
        try { await signInAsLocalAdmin() }
        catch { setError('Local admin sign-in failed. Start the Firebase emulators and run node functions/seed-local-admin.cjs.') }
        return
      }
      setUser(current); setRecords([]); setDeviceRecords([]); setPin(''); setShownPin(null); setIssued(false)
      if (!current) { setIsAdmin(false); setSyncing(false); return }
      try {
        const result = await current.getIdTokenResult()
        setSyncing(result.claims.admin === true)
        setIsAdmin(result.claims.admin === true)
        if (result.claims.admin !== true) setError('This account does not have administrator access.')
      } catch { setIsAdmin(false); setError('Could not verify administrator access.') }
    })
  }, [])

  useEffect(() => {
    if (!user || !isAdmin || !db) return
    return onSnapshot(query(collection(db, 'visitorAccess'), orderBy('createdAt', 'desc')), (snapshot) => {
      setRecords(snapshot.docs.map((item) => ({ id: item.id, ...item.data() })))
    }, () => setError('Could not load visitor access records.'))
  }, [user, isAdmin])

  useEffect(() => {
    if (!user || !isAdmin || !functions) return
    let active = true
    httpsCallable(functions, 'manageAccess')({ action: 'list' })
      .then((result) => { if (active) setDeviceRecords(result.data.records) })
      .catch((issue) => { if (active) setError(issue.message || 'Could not load temporary passwords from Tuya.') })
      .finally(() => { if (active) setSyncing(false) })
    return () => { active = false }
  }, [user, isAdmin])

  async function refreshAccess() {
    setSyncing(true); setError(''); setNotice('')
    try {
      const result = await httpsCallable(functions, 'manageAccess')({ action: 'list' })
      setDeviceRecords(result.data.records)
      setNotice(`Loaded ${result.data.records.length} current online temporary password records from Tuya.`)
    } catch (issue) { setDeviceRecords([]); setError(issue.message || 'Could not load temporary passwords from Tuya.') }
    finally { setSyncing(false) }
  }

  async function login(event) {
    event.preventDefault(); setBusy(true); setError('')
    try { await signInWithEmailAndPassword(auth, email, password); setLoginOpen(false); setPassword('') }
    catch { setError('Sign-in failed. Check your email and password.') }
    finally { setBusy(false) }
  }

  async function createAccess(event) {
    event.preventDefault()
    const start = Math.floor(new Date(form.start).getTime() / 1000)
    const end = Math.floor(new Date(form.end).getTime() / 1000)
    if (!form.name.trim() || !Number.isFinite(start) || !Number.isFinite(end) || end <= start || end <= Date.now() / 1000) { setError('Enter a name and a valid future access period.'); return }
    const nextPin = randomPin()
    setPin(nextPin); setIssued(false); setError(''); setNotice(''); setBusy(true)
    try {
      await httpsCallable(functions, 'manageAccess')({ action: 'create', requestId: crypto.randomUUID(), name: form.name, start, end, pin: nextPin })
      setIssued(true); setNotice('Tuya accepted the request. Check its status and test the PIN at the lock.'); setForm(freshForm())
    } catch (issue) { setError(issue.message || 'The request could not be completed. Check the Tuya app before retrying.') }
    finally { setBusy(false) }
  }

  async function manage(record, action) {
    if (action === 'revoke' && !window.confirm(`Request revocation for ${record.name}?`)) return
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await httpsCallable(functions, 'manageAccess')({ action, id: record.id })
      setDeviceRecords((current) => current.map((item) => item.passwordId === record.passwordId ? { ...item, state: result.data.state } : item))
      setNotice(action === 'revoke' ? 'Revocation requested. Check delivery before relying on it.' : `Delivery status: ${labels[result.data.state] || 'Needs review'}.`)
    } catch (issue) { setError(issue.message || 'The request failed. Check the Tuya app.') }
    finally { setBusy(false) }
  }

  async function copyPin() {
    try { await navigator.clipboard.writeText(pin); setCopied(true); setTimeout(() => setCopied(false), 2000) }
    catch { setError('Could not copy the PIN. Select it and copy it manually.') }
  }

  const deviceById = new Map(deviceRecords.map((record) => [record.passwordId, record]))
  const savedIds = new Set(records.map((record) => record.passwordId).filter(Boolean))
  const combined = [...records.map((record) => ({ ...record, ...deviceById.get(record.passwordId), id: record.id })), ...deviceRecords.filter((record) => !savedIds.has(record.passwordId)).map((record) => ({ ...record, id: `device-${record.passwordId}`, deviceOnly: true }))]
  const visible = combined.filter((record) => filter === 'all' || (filter === 'current' ? record.end > now / 1000 && !['revoked', 'failed'].includes(record.state) : record.end <= now / 1000 || ['revoked', 'failed'].includes(record.state))).sort((a, b) => sortAscending ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name))
  const currentCount = combined.filter((record) => record.start <= now / 1000 && record.end > now / 1000 && record.state === 'delivered').length
  const pendingCount = combined.filter((record) => ['submitting', 'pending', 'revoking', 'unknown'].includes(record.state)).length

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark"><DoorOpen size={22} /></div><div><strong>entry<span>desk</span></strong><small>ACCESS MANAGEMENT</small></div></div><div className="side-label">WORKSPACE</div><nav aria-label="Workspace"><button className={view === 'visitors' ? 'side-active side-link' : 'side-link'} aria-current={view === 'visitors' ? 'page' : undefined} onClick={() => setView('visitors')}><KeyRound size={17} /> Visitor access <span>01</span></button><button className={view === 'one-time' ? 'side-active side-link' : 'side-link'} aria-current={view === 'one-time' ? 'page' : undefined} onClick={() => setView('one-time')}><Clock3 size={17} /> One-time password <span>02</span></button></nav><div className="sidebar-bottom"><div className="side-lock"><div className="lock-icon"><DoorOpen size={19} /></div><div><strong>M-Link A6N</strong><small>Tuya smart lock</small></div></div><div className="secure-note"><ShieldCheck size={15} /> Admin access only</div></div></aside>
    <main className="main"><header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>{view === 'visitors' ? 'Visitor access' : 'One-time password'}</strong></div><div className="top-actions"><span className="connection"><span className={configured ? 'dot' : 'dot muted-dot'} /> {useEmulators ? 'Firebase local' : configured ? 'Firebase configured' : 'Setup required'}</span>{!useEmulators && (user ? <button className="text-button" onClick={() => signOut(auth)}><LogOut size={15} /> Sign out</button> : <button className="text-button" disabled={!configured} onClick={() => setLoginOpen(true)}>Admin sign in <ArrowRight size={15} /></button>)}</div></header>
      <div className="content"><div className="page-heading"><div><div className="eyebrow"><span /> ACCESS CONTROL</div><h1>{view === 'visitors' ? 'Visitor access' : 'One-time password'}</h1><p>{view === 'visitors' ? 'Manage temporary access for your door.' : 'Single-use visitor access.'}</p></div><div className="date-chip"><Clock3 size={15} /> {new Date(now).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}</div></div>
        {!configured && <div className="banner warning"><ShieldCheck size={18} /><div><strong>Connection setup required</strong><span>Configure Firebase and the Tuya Cloud Function before issuing access.</span></div></div>}
        {configured && !user && !useEmulators && <div className="banner warning"><ShieldCheck size={18} /><div><strong>Administrator sign-in required</strong><span>Sign in to manage visitor access.</span></div><button className="text-button" onClick={() => setLoginOpen(true)}>Sign in <ArrowRight size={15} /></button></div>}
        {error && <div className="banner error" role="alert"><div><strong>Action needs attention</strong><span>{error}</span></div><button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
        {notice && <div className="banner success" role="status"><Check size={18} /><div><strong>Request updated</strong><span>{notice}</span></div><button className="icon-button" onClick={() => setNotice('')} aria-label="Dismiss notice"><X size={16} /></button></div>}
        {view === 'visitors' ? <><div className="overview"><div><span className="overview-icon green"><Users size={18} /></span><div><small>CURRENT ACCESS</small><strong>{user && isAdmin ? String(currentCount).padStart(2, '0') : '--'}</strong></div></div><div><span className="overview-icon amber"><Clock3 size={18} /></span><div><small>NEEDS ATTENTION</small><strong>{user && isAdmin ? String(pendingCount).padStart(2, '0') : '--'}</strong></div></div><div><span className="overview-icon pale"><Wifi size={18} /></span><div><small>ACCESS METHOD</small><strong className="overview-text">Online PIN</strong></div></div><div className="overview-end"><span>YOUR LOCK</span><strong>M-Link A6N</strong><small>YS-WIFI_PRO</small></div></div>
        <div className="workspace"><section className="visitors"><div className="section-heading"><div className="section-kicker">ACCESS REGISTER</div><h2>Visitor passes <span>{user && isAdmin ? combined.length : '--'}</span></h2><p>Online temporary passwords from Tuya and this workspace</p><button className="text-button sync-button" onClick={refreshAccess} disabled={!user || !isAdmin || busy || syncing}><RefreshCw size={15} /> {syncing ? 'Loading...' : 'Refresh from Tuya'}</button></div><div className="table-tools"><div className="tabs" role="tablist" aria-label="Filter visitor passes">{[['all', 'All passes'], ['current', 'Current'], ['past', 'Past']].map(([value, label]) => <button key={value} role="tab" aria-selected={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div><span className="table-count">{visible.length} {visible.length === 1 ? 'pass' : 'passes'}</span></div><div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setSortAscending(!sortAscending)}>VISITOR <ArrowDownUp size={12} /></button></th><th>ACCESS PERIOD</th><th>DELIVERY</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visible.map((record) => <tr key={record.id}><td><div className="person"><span className="avatar">{record.name.slice(0, 1).toUpperCase()}</span><div><strong>{record.name}</strong><small>{shownPin === record.id && record.pin ? record.pin : record.deviceOnly ? 'Tuya app (read-only)' : 'Temporary PIN'}</small></div></div></td><td><strong className="date-main">{formatDate(record.start)}</strong><small className="date-sub">to {formatDate(record.end)}</small></td><td><span className={`status ${record.state}`}>{labels[record.state] || 'Needs review'}</span></td><td><div className="row-actions"><button className="icon-button" title={record.pin ? (shownPin === record.id ? 'Hide PIN' : 'Show PIN') : 'PIN unavailable'} aria-label={`${shownPin === record.id ? 'Hide' : 'Show'} PIN for ${record.name}`} disabled={!record.pin} onClick={() => setShownPin(shownPin === record.id ? null : record.id)}>{shownPin === record.id ? <EyeOff size={15} /> : <Eye size={15} />}</button><button className="icon-button" title={record.deviceOnly ? 'Manage this pass in Tuya' : 'Check delivery'} aria-label={`Check delivery for ${record.name}`} disabled={busy || !record.passwordId || record.deviceOnly} onClick={() => manage(record, 'check')}><RefreshCw size={15} /></button><button className="icon-button" title={record.deviceOnly ? 'Manage this pass in Tuya' : 'Revoke access'} aria-label={`Revoke access for ${record.name}`} disabled={busy || !record.passwordId || record.deviceOnly || ['revoked', 'revoking'].includes(record.state)} onClick={() => manage(record, 'revoke')}><Trash2 size={15} /></button></div></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty"><div className="empty-icon"><KeyRound size={20} /></div><strong>{!user || !isAdmin ? 'Your visitor passes will appear here' : 'No visitor passes found'}</strong><p>{!user || !isAdmin ? 'Sign in to view the access register.' : 'Create a pass or refresh from Tuya.'}</p></div>}</div><div className="table-footer"><span><ShieldCheck size={14} /> Tuya app PINs cannot be retrieved</span><span>Times shown in your local timezone</span></div></section>
          <section className="create-panel"><div className="panel-top"><div className="panel-icon"><KeyRound size={19} /></div><span>NEW PASS</span></div><h2>Create visitor PIN</h2><p className="panel-description">Set a temporary access window for your visitor.</p><form onSubmit={createAccess}><label>Visitor name<input required maxLength={80} placeholder="e.g. Alex Morgan" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label><div className="input-group"><label>Valid from<input required type="datetime-local" value={form.start} onChange={(event) => setForm({ ...form, start: event.target.value })} /></label><label>Expires on<input required type="datetime-local" value={form.end} onChange={(event) => setForm({ ...form, end: event.target.value })} /></label></div><div className="access-type"><div><span className="tiny-label">ACCESS TYPE</span><strong>Multiple use</strong></div><span>Within the selected period</span></div><button type="submit" className="primary-button" disabled={!user || !isAdmin || busy}><KeyRound size={16} /> {busy ? 'Please wait...' : 'Generate visitor PIN'} <ArrowRight size={16} /></button></form>{pin && <div className="pin-result"><div><span>{issued ? 'VISITOR PIN' : 'PIN FROM UNCONFIRMED REQUEST'}</span><strong>{pin}</strong><small>{issued ? 'Saved to Firebase. Confirm delivery before sharing.' : 'Check the Tuya app before retrying.'}</small></div><button className="icon-button" title="Copy PIN" aria-label="Copy PIN" onClick={copyPin}>{copied ? <Check size={17} /> : <Clipboard size={17} />}</button></div>}<div className="panel-foot"><ShieldCheck size={17} /><span>Confirm delivery before sharing the code with your visitor.</span></div></section></div>
        </> : <OneTimePasswords user={user} isAdmin={isAdmin} />}
        <footer className="footer"><span>ENTRYDESK / VISITOR ACCESS</span><span>Secure access, on your terms.</span></footer></div></main>
    {loginOpen && <div className="modal-backdrop" onClick={() => setLoginOpen(false)}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="login-title" onClick={(event) => event.stopPropagation()}><button className="icon-button modal-close" onClick={() => setLoginOpen(false)} aria-label="Close"><X size={18} /></button><div className="panel-icon"><ShieldCheck size={20} /></div><h2 id="login-title">Admin sign in</h2><p>Use your authorized Firebase account.</p><form onSubmit={login}><label>Email<input type="email" required autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Password<input type="password" required autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>{error && <p className="login-error">{error}</p>}<button className="primary-button" disabled={busy}>{busy ? 'Signing in...' : 'Sign in'} <ArrowRight size={16} /></button></form></div></div>}
  </div>
}

export default App