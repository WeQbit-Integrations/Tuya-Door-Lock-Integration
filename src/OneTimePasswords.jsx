import { useEffect, useState } from 'react'
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore'
import { httpsCallable } from 'firebase/functions'
import { ArrowDownUp, ArrowRight, Check, Clipboard, Eye, EyeOff, KeyRound, ShieldCheck, X } from 'lucide-react'
import { db, functions } from './firebase'

const formatDate = (seconds) => Number.isSafeInteger(seconds) ? new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '--'
const labels = { submitting: 'Submitting', generated: 'Generated', failed: 'Failed', unknown: 'Needs review' }

export default function OneTimePasswords({ user, isAdmin }) {
  const [records, setRecords] = useState([])
  const [name, setName] = useState('')
  const [result, setResult] = useState(null)
  const [shownPin, setShownPin] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [ascending, setAscending] = useState(true)

  useEffect(() => {
    if (!user || !isAdmin || !db) return
    return onSnapshot(query(collection(db, 'oneTimeAccess'), orderBy('createdAt', 'desc')), (snapshot) => {
      setRecords(snapshot.docs.map((item) => ({ id: item.id, ...item.data() })))
    }, () => setError('Could not load one-time passwords.'))
  }, [user, isAdmin])

  async function createPassword(event) {
    event.preventDefault()
    if (!name.trim()) { setError('Enter a visitor name.'); return }
    setBusy(true); setError(''); setResult(null)
    try {
      const response = await httpsCallable(functions, 'manageAccess')({ action: 'create-one-time', requestId: crypto.randomUUID(), name: name.trim() })
      setResult(response.data)
      if (!response.data.stored) setError('The password was generated but could not be saved to Firebase. Copy it now and check Tuya before retrying.')
      setName('')
    } catch (issue) { setError(issue.message || 'Could not generate the one-time password. Check Tuya before retrying.') }
    finally { setBusy(false) }
  }

  async function copyPassword() {
    try { await navigator.clipboard.writeText(result.pin); setCopied(true); setTimeout(() => setCopied(false), 2000) }
    catch { setError('Could not copy the password. Select it and copy it manually.') }
  }

  const visible = [...records].sort((first, second) => ascending ? first.name.localeCompare(second.name) : second.name.localeCompare(first.name))

  return <>
    {error && <div className="banner error" role="alert"><div><strong>Action needs attention</strong><span>{error}</span></div><button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
    <div className="workspace">
      <section className="visitors">
        <div className="section-heading"><div className="section-kicker">ACCESS REGISTER</div><h2>One-time passwords <span>{user && isAdmin ? records.length : '--'}</span></h2></div>
        <div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setAscending(!ascending)}>VISITOR <ArrowDownUp size={12} /></button></th><th>VALID UNTIL</th><th>STATUS</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visible.map((record) => <tr key={record.id}><td><div className="person"><span className="avatar">{record.name.slice(0, 1).toUpperCase()}</span><div><strong>{record.name}</strong><small>{shownPin === record.id && record.pin ? record.pin : 'One-time password'}</small></div></div></td><td><strong className="date-main">{formatDate(record.end)}</strong></td><td><span className={`status ${record.state}`}>{labels[record.state] || 'Needs review'}</span></td><td><button className="icon-button" title={record.pin ? (shownPin === record.id ? 'Hide password' : 'Show password') : 'Password unavailable'} aria-label={`${shownPin === record.id ? 'Hide' : 'Show'} password for ${record.name}`} disabled={!record.pin} onClick={() => setShownPin(shownPin === record.id ? null : record.id)}>{shownPin === record.id ? <EyeOff size={15} /> : <Eye size={15} />}</button></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty"><div className="empty-icon"><KeyRound size={20} /></div><strong>No one-time passwords</strong></div>}</div>
        <div className="table-footer"><span><ShieldCheck size={14} /> Usage is not verified by this list</span><span>Times shown in your local timezone</span></div>
      </section>
      <section className="create-panel"><div className="panel-top"><div className="panel-icon"><KeyRound size={19} /></div><span>ONE-TIME ACCESS</span></div><h2>Create one-time password</h2><form onSubmit={createPassword}><label>Visitor name<input required maxLength={80} placeholder="e.g. Alex Morgan" value={name} onChange={(event) => setName(event.target.value)} /></label><div className="access-type"><div><span className="tiny-label">ACCESS TYPE</span><strong>One use</strong></div><span>Offline password</span></div><button className="primary-button" disabled={!user || !isAdmin || busy}><KeyRound size={16} /> {busy ? 'Generating...' : 'Generate password'} <ArrowRight size={16} /></button></form>{result && <div className="pin-result"><div><span>ONE-TIME PASSWORD</span><strong>{result.pin}</strong><small>Valid until {formatDate(result.end)}</small></div><button className="icon-button" title="Copy password" aria-label="Copy password" onClick={copyPassword}>{copied ? <Check size={17} /> : <Clipboard size={17} />}</button></div>}</section>
    </div>
  </>
}