import { useEffect, useState } from 'react'
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore'
import { httpsCallable } from 'firebase/functions'
import { AlertTriangle, ArrowDownUp, ArrowRight, Check, Clipboard, Eye, EyeOff, History, KeyRound, RefreshCw, ShieldCheck, Trash2, Users, X } from 'lucide-react'
import { db, functions } from './firebase'

const formatDate = (seconds) => Number.isSafeInteger(seconds) ? new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '--'
const localInput = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
const labels = { submitting: 'Submitting', generated: 'Generated', used: 'Used once', invalid: 'Invalid', 'purge-submitted': 'Purge requested', failed: 'Failed', unknown: 'Needs review' }

export default function OneTimePasswords({ user, isAdmin, mode = 'one-time', onShowLogs }) {
  const multiple = mode === 'offline'
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(mode !== 'offline')
  const [name, setName] = useState('')
  const [start, setStart] = useState(() => localInput(new Date()))
  const [end, setEnd] = useState(() => localInput(new Date(Date.now() + 86400000)))
  const [result, setResult] = useState(null)
  const [shownPin, setShownPin] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [clearAllConfirmOpen, setClearAllConfirmOpen] = useState(false)
  const [clearAllPhrase, setClearAllPhrase] = useState('')
  const [copied, setCopied] = useState(false)
  const [ascending, setAscending] = useState(true)
  const [filter, setFilter] = useState('all')

  async function fetchTuyaOneTimeRecords() {
    const allRecords = []
    for (let page = 1; page <= 1000; page += 1) {
      const response = await httpsCallable(functions, 'manageAccess')({ action: 'list-tuya-one-time', page })
      allRecords.push(...response.data.records)
      if (!response.data.hasMore) return allRecords
    }
    throw new Error('Tuya returned too many pages to load safely.')
  }

  useEffect(() => {
    if (!user || !isAdmin) return
    if (multiple) {
      if (!db) return
      return onSnapshot(query(collection(db, 'offlineAccess'), orderBy('createdAt', 'desc')), (snapshot) => {
        setRecords(snapshot.docs.map((item) => ({ id: item.id, ...item.data() })))
      }, () => setError('Could not load offline passwords.'))
    }
    if (!functions) return
    let active = true
    fetchTuyaOneTimeRecords()
      .then((tuyaRecords) => { if (active) setRecords(tuyaRecords) })
      .catch((issue) => { if (active) setError(issue.message || 'Could not load one-time passwords from Tuya.') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [user, isAdmin, multiple])

  async function refreshTuyaOneTimeRecords() {
    setLoading(true); setError('')
    try { setRecords(await fetchTuyaOneTimeRecords()) }
    catch (issue) { setError(issue.message || 'Could not load one-time passwords from Tuya.') }
    finally { setLoading(false) }
  }

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
      else if (!multiple) {
        try { setRecords(await fetchTuyaOneTimeRecords()) }
        catch { setError('The password was generated, but Tuya\'s one-time list could not be refreshed.') }
      }
      setName('')
    } catch (issue) { setError(issue.message || 'Could not generate the offline password. Check Tuya before retrying.') }
    finally { setBusy(false) }
  }

  async function copyPassword() {
    try { await navigator.clipboard.writeText(result.pin); setCopied(true); setTimeout(() => setCopied(false), 2000) }
    catch { setError('Could not copy the password. Select it and copy it manually.') }
  }

  async function purgePassword(record) {
    if (record.purgeState === 'pending') return
    const retry = record.purgeState === 'unknown'
    const prompt = `Request Tuya to purge the one-time password for ${record.name}? Tuya does not report whether it has already been used.${retry ? ' The previous purge result was uncertain; check Tuya before retrying.' : ''} This affects only this saved key.`
    if (!window.confirm(prompt)) return
    setBusy(true); setError(''); setNotice('')
    try {
      await httpsCallable(functions, 'manageAccess')({ action: 'purge-one-time', id: record.id })
      setRecords((current) => current.map((item) => item.id === record.id ? { ...item, state: 'purge-submitted', purgeState: 'submitted' } : item))
      setNotice(`Tuya accepted the purge request for ${record.name}. Lock-side removal is not independently verified; the history record was retained.`)
    } catch (issue) { setError(issue.message || 'Tuya did not confirm the purge. Check Tuya before retrying.') }
    finally { setBusy(false) }
  }

  async function clearAllOfflinePasswords(event) {
    event.preventDefault()
    const phrase = 'CLEAR ALL OFFLINE PASSWORDS'
    if (clearAllPhrase !== phrase) return
    setClearAllConfirmOpen(false); setClearAllPhrase('')
    setBusy(true); setError(''); setNotice('')
    try {
      const response = await httpsCallable(functions, 'manageAccess')({ action: 'purge-all-offline', requestId: crypto.randomUUID(), confirmation: phrase })
      setRecords((current) => current.map((record) => record.passwordId ? { ...record, state: 'purge-submitted', purgeState: 'submitted' } : record))
      setNotice(`Tuya accepted the clear-all request. ${response.data.updatedRecords} website records were updated. Online temporary PINs were not affected; lock-side removal is not independently verified.`)
    } catch (issue) { setError(issue.message || 'Tuya did not confirm clearing offline passwords. Check Tuya before retrying.') }
    finally { setBusy(false) }
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
    {notice && <div className="banner success" role="status"><Check size={18} /><div><strong>Purge request accepted</strong><span>{notice}</span></div><button className="icon-button" onClick={() => setNotice('')} aria-label="Dismiss notice"><X size={16} /></button></div>}
    {multiple && <div className="banner warning" role="status"><ShieldCheck size={18} /><div><strong>Lock validity is unverified</strong><span>Tuya's app and API can show different times. Confirm the lock's start and expiry before relying on this password.</span></div></div>}
    {adjusted && <div className="banner warning" role="status"><div><strong>Tuya adjusted the access window</strong><span>The API-returned times differ from your request and may also differ from the lock's actual validity.</span></div></div>}
    <div className={multiple ? 'workspace offline-workspace' : 'workspace'}>
      <section className="visitors">
        <div className="section-heading"><div className="section-kicker">ACCESS REGISTER</div><h2>{multiple ? 'Offline visitor passwords' : 'One-time passwords'} <span>{user && isAdmin ? records.length : '--'}</span></h2>{!multiple && <><button className="text-button sync-button" disabled={!user || !isAdmin || busy || loading} onClick={refreshTuyaOneTimeRecords}><RefreshCw size={15} /> {loading ? 'Loading from Tuya...' : 'Refresh from Tuya'}</button><div className="offline-clear-warning"><AlertTriangle size={15} /><span>Clear all affects every offline key, including reusable and Tuya-app-created keys. Online temporary PINs are not affected.</span></div><button className="text-button clear-all-button" disabled={!user || !isAdmin || busy} onClick={() => { setClearAllPhrase(''); setClearAllConfirmOpen(true) }}><Trash2 size={15} /> Clear all offline passwords</button></>}</div>
        {multiple && <div className="table-tools"><div className="tabs" role="tablist" aria-label="Filter offline passwords">{[['all', 'All passwords'], ['generated', 'Generated'], ['attention', 'Needs review']].map(([value, label]) => <button key={value} role="tab" aria-selected={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div><span className="table-count">{visible.length} {visible.length === 1 ? 'password' : 'passwords'}</span></div>}
        <div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setAscending(!ascending)}>VISITOR <ArrowDownUp size={12} /></button></th><th>{multiple ? 'TUYA API PERIOD' : 'VALID UNTIL'}</th>{!multiple && <th>TUYA CLOUD DATA</th>}<th>STATUS</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visible.map((record) => <tr key={record.id}><td><div className="person"><span className="avatar">{record.name.slice(0, 1).toUpperCase()}</span><div><strong>{record.name}</strong><small>{shownPin === record.id && record.pin ? record.pin : multiple ? 'Offline password' : record.sourceTuya ? 'Tuya offline password' : 'One-time password'}</small></div></div></td><td>{multiple && <strong className="date-main">{formatDate(record.start)}</strong>}<small className="date-sub">{multiple ? 'to ' : ''}{formatDate(record.end)}</small>{multiple && Number.isSafeInteger(record.requestedStart) && Number.isSafeInteger(record.requestedEnd) && <><small className="date-sub">Requested: {formatDate(record.requestedStart)}</small><small className="date-sub">to {formatDate(record.requestedEnd)}</small></>}</td>{!multiple && <td><div className="tuya-cloud-data"><small>Key ID: {record.passwordId}</small><small>Type: {record.type} (code {record.passwordType ?? 'not reported'})</small><small>Created: {formatDate(record.createdAt)}</small><small>Starts: {formatDate(record.start)}</small><small>Expires: {formatDate(record.end)}</small><small>Time zone: {record.timeZone || 'Not reported'}</small><small>Clear code: {record.hasClearPassword === true ? 'Available' : record.hasClearPassword === false ? 'No' : 'Not reported'}</small><small>Tuya status: {labels[record.state] || 'Needs review'} (code {record.statusCode ?? 'not reported'})</small></div></td>}<td><span className={`status ${record.state === 'purge-submitted' ? 'unknown' : record.state}`}>{labels[record.state] || 'Needs review'}</span></td><td><div className="row-actions"><button className="icon-button" title={record.pin ? (shownPin === record.id ? 'Hide password' : 'Show password') : 'PIN digits unavailable from Tuya'} aria-label={`${shownPin === record.id ? 'Hide' : 'Show'} password for ${record.name}`} disabled={!record.pin} onClick={() => setShownPin(shownPin === record.id ? null : record.id)}>{shownPin === record.id ? <EyeOff size={15} /> : <Eye size={15} />}</button><button className="icon-button" title="Usage logs" aria-label={`Usage logs for ${record.name}`} onClick={() => onShowLogs(record)}><History size={15} /></button>{!multiple && !record.sourceTuya && <button className="icon-button" title={record.state === 'purge-submitted' ? 'Purge request already accepted' : !record.passwordId ? 'No saved Tuya ID; cannot purge' : record.purgeState === 'unknown' ? 'Check Tuya, then retry purge' : 'Purge this one-time key from Tuya'} aria-label={`Purge one-time password for ${record.name}`} disabled={busy || record.state === 'purge-submitted' || record.purgeState === 'pending' || !record.passwordId} onClick={() => purgePassword(record)}><Trash2 size={15} /></button>}</div></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty"><div className="empty-icon"><KeyRound size={20} /></div><strong>{!multiple && user && isAdmin && loading ? 'Loading one-time passwords from Tuya...' : multiple ? 'No offline visitor passwords' : 'No Tuya one-time passwords found'}</strong></div>}</div>
        <div className="table-footer"><span><ShieldCheck size={14} /> {multiple ? 'Usage is not verified by this list' : 'Tuya list metadata only; PIN digits are not returned'}</span><span>Times shown in your local timezone</span></div>
      </section>
      <section className={multiple ? 'create-panel offline-create' : 'create-panel'}><div className="panel-top"><div className="panel-icon"><KeyRound size={19} /></div><span>{multiple ? 'NEW VISITOR PASSWORD' : 'ONE-TIME ACCESS'}</span></div><h2>{multiple ? 'Create offline visitor password' : 'Create one-time password'}</h2><form onSubmit={createPassword}><label>Visitor name<input required maxLength={80} placeholder="e.g. Alex Morgan" value={name} onChange={(event) => setName(event.target.value)} /></label>{multiple && <div className="input-group"><label>Valid from<input required type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} /></label><label>Expires on<input required type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} /></label></div>}<div className="access-type"><div><span className="tiny-label">ACCESS TYPE</span><strong>{multiple ? 'Multiple use' : 'One use'}</strong></div><span>Offline password</span></div><button className="primary-button" disabled={!user || !isAdmin || busy}><KeyRound size={16} /> {busy ? 'Generating...' : 'Generate password'} <ArrowRight size={16} /></button></form>{displayedResult && <div className="pin-result"><div><span>{multiple ? 'OFFLINE VISITOR PASSWORD' : 'ONE-TIME PASSWORD'}</span><strong>{displayedResult.pin}</strong>{multiple && <><small>Requested start: {formatDate(displayedResult.requestedStart)}</small><small>Requested expiry: {formatDate(displayedResult.requestedEnd)}</small><small>Tuya API start: {formatDate(displayedResult.start)}</small></>}<small>{multiple ? 'Tuya API expiry' : 'Valid until'}: {formatDate(displayedResult.end)}</small></div><button className="icon-button" title="Copy password" aria-label="Copy password" onClick={copyPassword}>{copied ? <Check size={17} /> : <Clipboard size={17} />}</button></div>}</section>
    </div>
    {clearAllConfirmOpen && <div className="modal-backdrop" onClick={() => setClearAllConfirmOpen(false)}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="clear-all-title" onClick={(event) => event.stopPropagation()}><button className="icon-button modal-close" onClick={() => setClearAllConfirmOpen(false)} aria-label="Cancel clear all"><X size={18} /></button><div className="panel-icon"><AlertTriangle size={20} /></div><h2 id="clear-all-title">Clear all offline passwords?</h2><p>This asks Tuya to clear every offline password on the lock, including one-time, reusable, and Tuya-app-created offline passwords. It does not clear online temporary PINs. Lock-side removal cannot be independently verified.</p><form onSubmit={clearAllOfflinePasswords}><label>Type <strong>CLEAR ALL OFFLINE PASSWORDS</strong> to confirm<input autoComplete="off" value={clearAllPhrase} onChange={(event) => setClearAllPhrase(event.target.value)} /></label><div className="modal-actions"><button type="button" className="text-button" onClick={() => setClearAllConfirmOpen(false)}>Cancel</button><button type="submit" className="danger-button" disabled={clearAllPhrase !== 'CLEAR ALL OFFLINE PASSWORDS' || busy}><Trash2 size={15} /> Clear offline passwords</button></div></form></div></div>}
  </>
}