import { useEffect, useState } from 'react'
import { onAuthStateChanged, signInWithEmailAndPassword, signOut } from 'firebase/auth'
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore'
import { httpsCallable } from 'firebase/functions'
import { ArrowDownUp, ArrowRight, Check, Clock3, DoorOpen, Eye, EyeOff, History, KeyRound, LogOut, RefreshCw, ShieldCheck, Trash2, Users, Wifi, X } from 'lucide-react'
import { auth, db, functions, configured, useEmulators, signInAsLocalAdmin } from './firebase'
import OneTimePasswords from './OneTimePasswords'
import UsageLogs from './UsageLogs'
import './App.css'

const formatDate = (seconds) => new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })
const labels = { submitting: 'Submitting', pending: 'Awaiting delivery', delivered: 'Sent to lock', revoking: 'Revocation pending', revoked: 'Tuya reports deleted', failed: 'Failed', unknown: 'Needs review' }

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
  const [shownPin, setShownPin] = useState(null)
  const [logRecord, setLogRecord] = useState(null)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [filter, setFilter] = useState('all')
  const [sortAscending, setSortAscending] = useState(true)
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
      setIsAdmin(false); setUser(current); setRecords([]); setDeviceRecords([]); setShownPin(null); setLogRecord(null)
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

  const deviceById = new Map(deviceRecords.map((record) => [record.passwordId, record]))
  const savedIds = new Set(records.map((record) => record.passwordId).filter(Boolean))
  const combined = [...records.map((record) => ({ ...record, ...deviceById.get(record.passwordId), id: record.id })), ...deviceRecords.filter((record) => !savedIds.has(record.passwordId)).map((record) => ({ ...record, id: `device-${record.passwordId}`, deviceOnly: true }))]
  const visible = combined.filter((record) => filter === 'all' || (filter === 'current' ? record.end > now / 1000 && !['revoked', 'failed'].includes(record.state) : record.end <= now / 1000 || ['revoked', 'failed'].includes(record.state))).sort((a, b) => sortAscending ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name))
  const currentCount = combined.filter((record) => record.start <= now / 1000 && record.end > now / 1000 && record.state === 'delivered').length
  const pendingCount = combined.filter((record) => ['submitting', 'pending', 'revoking', 'unknown'].includes(record.state)).length
  const viewTitle = view === 'visitors' ? 'Visitor access' : view === 'offline' ? 'Offline visitor access' : 'One-time password'

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark"><DoorOpen size={22} /></div><div><strong>entry<span>desk</span></strong><small>ACCESS MANAGEMENT</small></div></div><div className="side-label">WORKSPACE</div><nav aria-label="Workspace"><button className={view === 'visitors' ? 'side-active side-link' : 'side-link'} aria-current={view === 'visitors' ? 'page' : undefined} onClick={() => setView('visitors')}><KeyRound size={17} /> Visitor access <span>01</span></button><button className={view === 'one-time' ? 'side-active side-link' : 'side-link'} aria-current={view === 'one-time' ? 'page' : undefined} onClick={() => setView('one-time')}><Clock3 size={17} /> One-time password <span>02</span></button><button className={view === 'offline' ? 'side-active side-link' : 'side-link'} aria-current={view === 'offline' ? 'page' : undefined} onClick={() => setView('offline')}><KeyRound size={17} /> Offline visitor access <span>03</span></button></nav><div className="sidebar-bottom"><div className="side-lock"><div className="lock-icon"><DoorOpen size={19} /></div><div><strong>M-Link A6N</strong><small>Tuya smart lock</small></div></div><div className="secure-note"><ShieldCheck size={15} /> Admin access only</div></div></aside>
    <main className="main"><header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>{viewTitle}</strong></div><div className="top-actions"><span className="connection"><span className={configured ? 'dot' : 'dot muted-dot'} /> {useEmulators ? 'Firebase local' : configured ? 'Firebase configured' : 'Setup required'}</span>{!useEmulators && (user ? <button className="text-button" onClick={() => signOut(auth)}><LogOut size={15} /> Sign out</button> : <button className="text-button" disabled={!configured} onClick={() => setLoginOpen(true)}>Admin sign in <ArrowRight size={15} /></button>)}</div></header>
      <div className="content"><div className="page-heading"><div><div className="eyebrow"><span /> ACCESS CONTROL</div><h1>{viewTitle}</h1><p>{view === 'visitors' ? 'Manage temporary access for your door.' : view === 'offline' ? 'Time-limited, multiple-use visitor access.' : 'Single-use visitor access.'}</p></div><div className="date-chip"><Clock3 size={15} /> {new Date(now).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}</div></div>
        {!configured && <div className="banner warning"><ShieldCheck size={18} /><div><strong>Connection setup required</strong><span>Configure Firebase and the Tuya Cloud Function before issuing access.</span></div></div>}
        {configured && !user && !useEmulators && <div className="banner warning"><ShieldCheck size={18} /><div><strong>Administrator sign-in required</strong><span>Sign in to manage visitor access.</span></div><button className="text-button" onClick={() => setLoginOpen(true)}>Sign in <ArrowRight size={15} /></button></div>}
        {error && <div className="banner error" role="alert"><div><strong>Action needs attention</strong><span>{error}</span></div><button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
        {notice && <div className="banner success" role="status"><Check size={18} /><div><strong>Request updated</strong><span>{notice}</span></div><button className="icon-button" onClick={() => setNotice('')} aria-label="Dismiss notice"><X size={16} /></button></div>}
        {view === 'visitors' ? <><div className="overview"><div><span className="overview-icon green"><Users size={18} /></span><div><small>CURRENT ACCESS</small><strong>{user && isAdmin ? String(currentCount).padStart(2, '0') : '--'}</strong></div></div><div><span className="overview-icon amber"><Clock3 size={18} /></span><div><small>NEEDS ATTENTION</small><strong>{user && isAdmin ? String(pendingCount).padStart(2, '0') : '--'}</strong></div></div><div><span className="overview-icon pale"><Wifi size={18} /></span><div><small>ACCESS METHOD</small><strong className="overview-text">Online PIN</strong></div></div><div className="overview-end"><span>YOUR LOCK</span><strong>M-Link A6N</strong><small>YS-WIFI_PRO</small></div></div>
        <div className="workspace"><section className="visitors"><div className="section-heading"><div className="section-kicker">ACCESS REGISTER</div><h2>Visitor passes <span>{user && isAdmin ? combined.length : '--'}</span></h2><p>Online temporary passwords from Tuya and this workspace</p><button className="text-button sync-button" onClick={refreshAccess} disabled={!user || !isAdmin || busy || syncing}><RefreshCw size={15} /> {syncing ? 'Loading...' : 'Refresh from Tuya'}</button></div><div className="table-tools"><div className="tabs" role="tablist" aria-label="Filter visitor passes">{[['all', 'All passes'], ['current', 'Current'], ['past', 'Past']].map(([value, label]) => <button key={value} role="tab" aria-selected={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div><span className="table-count">{visible.length} {visible.length === 1 ? 'pass' : 'passes'}</span></div><div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setSortAscending(!sortAscending)}>VISITOR <ArrowDownUp size={12} /></button></th><th>ACCESS PERIOD</th><th>DELIVERY</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visible.map((record) => <tr key={record.id}><td><div className="person"><span className="avatar">{record.name.slice(0, 1).toUpperCase()}</span><div><strong>{record.name}</strong><small>{shownPin === record.id && record.pin ? record.pin : record.deviceOnly ? 'Tuya app (read-only)' : 'Temporary PIN'}</small></div></div></td><td><strong className="date-main">{formatDate(record.start)}</strong><small className="date-sub">to {formatDate(record.end)}</small></td><td><span className={`status ${record.state}`}>{labels[record.state] || 'Needs review'}</span></td><td><div className="row-actions"><button className="icon-button" title={record.pin ? (shownPin === record.id ? 'Hide PIN' : 'Show PIN') : 'PIN unavailable'} aria-label={`${shownPin === record.id ? 'Hide' : 'Show'} PIN for ${record.name}`} disabled={!record.pin} onClick={() => setShownPin(shownPin === record.id ? null : record.id)}>{shownPin === record.id ? <EyeOff size={15} /> : <Eye size={15} />}</button><button className="icon-button" title="Usage logs" aria-label={`Usage logs for ${record.name}`} onClick={() => setLogRecord(record)}><History size={15} /></button><button className="icon-button" title={record.deviceOnly ? 'Manage this pass in Tuya' : 'Check delivery'} aria-label={`Check delivery for ${record.name}`} disabled={busy || !record.passwordId || record.deviceOnly} onClick={() => manage(record, 'check')}><RefreshCw size={15} /></button><button className="icon-button" title={record.deviceOnly ? 'Manage this pass in Tuya' : 'Revoke access'} aria-label={`Revoke access for ${record.name}`} disabled={busy || !record.passwordId || record.deviceOnly || ['revoked', 'revoking'].includes(record.state)} onClick={() => manage(record, 'revoke')}><Trash2 size={15} /></button></div></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty"><div className="empty-icon"><KeyRound size={20} /></div><strong>{!user || !isAdmin ? 'Your visitor passes will appear here' : 'No visitor passes found'}</strong><p>{!user || !isAdmin ? 'Sign in to view the access register.' : 'Create a pass or refresh from Tuya.'}</p></div>}</div><div className="table-footer"><span><ShieldCheck size={14} /> Tuya app PINs cannot be retrieved</span><span>Times shown in your local timezone</span></div></section>
        </div>
        </> : <OneTimePasswords key={view} user={user} isAdmin={isAdmin} mode={view} onShowLogs={setLogRecord} />}
        <footer className="footer"><span>ENTRYDESK / VISITOR ACCESS</span><span>Secure access, on your terms.</span></footer></div></main>
    {logRecord && <UsageLogs key={logRecord.id} record={logRecord} user={user} isAdmin={isAdmin} onClose={() => setLogRecord(null)} />}
    {loginOpen && <div className="modal-backdrop" onClick={() => setLoginOpen(false)}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="login-title" onClick={(event) => event.stopPropagation()}><button className="icon-button modal-close" onClick={() => setLoginOpen(false)} aria-label="Close"><X size={18} /></button><div className="panel-icon"><ShieldCheck size={20} /></div><h2 id="login-title">Admin sign in</h2><p>Use your authorized Firebase account.</p><form onSubmit={login}><label>Email<input type="email" required autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Password<input type="password" required autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>{error && <p className="login-error">{error}</p>}<button className="primary-button" disabled={busy}>{busy ? 'Signing in...' : 'Sign in'} <ArrowRight size={16} /></button></form></div></div>}
  </div>
}

export default App