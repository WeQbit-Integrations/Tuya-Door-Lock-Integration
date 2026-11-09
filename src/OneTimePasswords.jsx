import { useEffect, useState } from 'react'
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore'
import { httpsCallable } from 'firebase/functions'
import { AlertTriangle, ArrowDownUp, ArrowRight, Check, Clipboard, Eye, EyeOff, History, KeyRound, ShieldCheck, Users, X } from 'lucide-react'
import { db, functions } from './firebase'

const formatDate = (seconds) => Number.isSafeInteger(seconds) ? new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '--'
const localInput = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
const labels = { submitting: 'Submitting', generated: 'Generated', failed: 'Failed', unknown: 'Needs review' }

export default function OneTimePasswords({ user, isAdmin, mode = 'one-time', onShowLogs }) {
  const multiple = mode === 'offline'
  const [records, setRecords] = useState([])
  const [name, setName] = useState('')
  const [start, setStart] = useState(() => localInput(new Date()))
  const [end, setEnd] = useState(() => localInput(new Date(Date.now() + 86400000)))
  const [result, setResult] = useState(null)
  const [shownPin, setShownPin] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [ascending, setAscending] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    if (!user || !isAdmin || !db) return
    return onSnapshot(query(collection(db, multiple ? 'offlineAccess' : 'oneTimeAccess'), orderBy('createdAt', 'desc')), (snapshot) => {
      setRecords(snapshot.docs.map((item) => ({ id: item.id, ...item.data() })))
    }, () => setError('Could not load offline passwords.'))
  }, [user, isAdmin, multiple])

  async function createPassword(event) {
    event.preventDefault()
    if (!name.trim()) { setError('Enter a visitor name.'); return }
    const requestedStart = multiple ? Math.floor(new Date(start).getTime() / 1000) : null
    const requestedEnd = multiple ? Math.floor(new Date(end).getTime() / 1000) : null
    if (multiple && (!Number.isSafeInteger(requestedStart) || !Number.isSafeInteger(requestedEnd) || requestedEnd <= requestedStart || requestedEnd <= Date.now() / 1000)) { setError('Select a valid start and future expiration time.'); return }
    setBusy(true); setError(''); setResult(null)
    try {
      const request = { action: multiple ? 'create-offline' : 'create-one-time', requestId: crypto.randomUUID(), name: name.trim(), ...(multiple ? { start: requestedStart, end: requestedEnd } : {}) }
      const response = await httpsCallable(functions, 'manageAccess')(request)
      setResult({ ...response.data, requestedStart, requestedEnd })
      if (!response.data.stored) setError('The password was generated but could not be saved to Firebase. Copy it now and check Tuya before retrying.')
      setName('')
    } catch (issue) { setError(issue.message || 'Could not generate the offline password. Check Tuya before retrying.') }
    finally { setBusy(false) }
  }

  async function copyPassword() {
    try { await navigator.clipboard.writeText(result.pin); setCopied(true); setTimeout(() => setCopied(false), 2000) }
    catch { setError('Could not copy the password. Select it and copy it manually.') }
  }

  const generatedCount = records.filter((record) => record.state === 'generated').length
  const attentionCount = records.filter((record) => ['failed', 'unknown'].includes(record.state)).length
  const visible = user && isAdmin ? records.filter((record) => !multiple || filter === 'all' || (filter === 'generated' ? record.state === 'generated' : ['failed', 'unknown'].includes(record.state))).sort((first, second) => ascending ? first.name.localeCompare(second.name) : second.name.localeCompare(first.name)) : []
  const displayedResult = user && isAdmin ? result : null
  const adjusted = multiple && displayedResult && (displayedResult.start !== displayedResult.requestedStart || displayedResult.end !== displayedResult.requestedEnd)

  return <>
    {multiple && <div className="overview">
      <div><span className="overview-icon green"><Users size={18} /></span><div><small>GENERATED PASSWORDS</small><strong>{user && isAdmin ? String(generatedCount).padStart(2, '0') : '--'}</strong></div></div>
      <div><span className="overview-icon amber"><AlertTriangle size={18} /></span><div><small>NEEDS ATTENTION</small><strong>{user && isAdmin ? String(attentionCount).padStart(2, '0') : '--'}</strong></div></div>
      <div><span className="overview-icon pale"><KeyRound size={18} /></span><div><small>ACCESS METHOD</small><strong className="overview-text">Offline PIN</strong></div></div>
      <div className="overview-end"><span>YOUR LOCK</span><strong>M-Link A6N</strong><small>YS-WIFI_PRO</small></div>
    </div>}
    {error && <div className="banner error" role="alert"><div><strong>Action needs attention</strong><span>{error}</span></div><button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
    {multiple && <div className="banner warning" role="status"><ShieldCheck size={18} /><div><strong>Lock validity is unverified</strong><span>Tuya's app and API can show different times. Confirm the lock's start and expiry before relying on this password.</span></div></div>}
    {adjusted && <div className="banner warning" role="status"><div><strong>Tuya adjusted the access window</strong><span>The API-returned times differ from your request and may also differ from the lock's actual validity.</span></div></div>}
    <div className={multiple ? 'workspace offline-workspace' : 'workspace'}>
      <section className="visitors">
        <div className="section-heading"><div className="section-kicker">ACCESS REGISTER</div><h2>{multiple ? 'Offline visitor passwords' : 'One-time passwords'} <span>{user && isAdmin ? records.length : '--'}</span></h2></div>
        {multiple && <div className="table-tools"><div className="tabs" role="tablist" aria-label="Filter offline passwords">{[['all', 'All passwords'], ['generated', 'Generated'], ['attention', 'Needs review']].map(([value, label]) => <button key={value} role="tab" aria-selected={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div><span className="table-count">{visible.length} {visible.length === 1 ? 'password' : 'passwords'}</span></div>}
        <div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setAscending(!ascending)}>VISITOR <ArrowDownUp size={12} /></button></th><th>{multiple ? 'TUYA API PERIOD' : 'VALID UNTIL'}</th><th>STATUS</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visible.map((record) => <tr key={record.id}><td><div className="person"><span className="avatar">{record.name.slice(0, 1).toUpperCase()}</span><div><strong>{record.name}</strong><small>{shownPin === record.id && record.pin ? record.pin : multiple ? 'Offline password' : 'One-time password'}</small></div></div></td><td>{multiple && <strong className="date-main">{formatDate(record.start)}</strong>}<small className="date-sub">{multiple ? 'to ' : ''}{formatDate(record.end)}</small>{multiple && Number.isSafeInteger(record.requestedStart) && Number.isSafeInteger(record.requestedEnd) && <><small className="date-sub">Requested: {formatDate(record.requestedStart)}</small><small className="date-sub">to {formatDate(record.requestedEnd)}</small></>}</td><td><span className={`status ${record.state}`}>{labels[record.state] || 'Needs review'}</span></td><td><div className="row-actions"><button className="icon-button" title={record.pin ? (shownPin === record.id ? 'Hide password' : 'Show password') : 'Password unavailable'} aria-label={`${shownPin === record.id ? 'Hide' : 'Show'} password for ${record.name}`} disabled={!record.pin} onClick={() => setShownPin(shownPin === record.id ? null : record.id)}>{shownPin === record.id ? <EyeOff size={15} /> : <Eye size={15} />}</button><button className="icon-button" title="Usage logs" aria-label={`Usage logs for ${record.name}`} onClick={() => onShowLogs(record)}><History size={15} /></button></div></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty"><div className="empty-icon"><KeyRound size={20} /></div><strong>{multiple ? 'No offline visitor passwords' : 'No one-time passwords'}</strong></div>}</div>
        <div className="table-footer"><span><ShieldCheck size={14} /> Usage is not verified by this list</span><span>Times shown in your local timezone</span></div>
      </section>
      <section className={multiple ? 'create-panel offline-create' : 'create-panel'}><div className="panel-top"><div className="panel-icon"><KeyRound size={19} /></div><span>{multiple ? 'NEW VISITOR PASSWORD' : 'ONE-TIME ACCESS'}</span></div><h2>{multiple ? 'Create offline visitor password' : 'Create one-time password'}</h2><form onSubmit={createPassword}><label>Visitor name<input required maxLength={80} placeholder="e.g. Alex Morgan" value={name} onChange={(event) => setName(event.target.value)} /></label>{multiple && <div className="input-group"><label>Valid from<input required type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} /></label><label>Expires on<input required type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} /></label></div>}<div className="access-type"><div><span className="tiny-label">ACCESS TYPE</span><strong>{multiple ? 'Multiple use' : 'One use'}</strong></div><span>Offline password</span></div><button className="primary-button" disabled={!user || !isAdmin || busy}><KeyRound size={16} /> {busy ? 'Generating...' : 'Generate password'} <ArrowRight size={16} /></button></form>{displayedResult && <div className="pin-result"><div><span>{multiple ? 'OFFLINE VISITOR PASSWORD' : 'ONE-TIME PASSWORD'}</span><strong>{displayedResult.pin}</strong>{multiple && <><small>Requested start: {formatDate(displayedResult.requestedStart)}</small><small>Requested expiry: {formatDate(displayedResult.requestedEnd)}</small><small>Tuya API start: {formatDate(displayedResult.start)}</small></>}<small>{multiple ? 'Tuya API expiry' : 'Valid until'}: {formatDate(displayedResult.end)}</small></div><button className="icon-button" title="Copy password" aria-label="Copy password" onClick={copyPassword}>{copied ? <Check size={17} /> : <Clipboard size={17} />}</button></div>}</section>
    </div>
  </>
}