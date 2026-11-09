import { useEffect, useRef, useState } from 'react'
import { httpsCallable } from 'firebase/functions'
import { AlertTriangle, ArrowDownUp, ChevronLeft, ChevronRight, History, RefreshCw, X } from 'lucide-react'
import { functions } from './firebase'

const localInput = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
const formatDate = (seconds) => new Date(seconds * 1000).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' })
const methods = { unlock_temporary: 'Temporary password', unlock_offline_pd: 'Offline password', unlock_password: 'Password', unlock_dynamic: 'Dynamic password', unlock_fingerprint: 'Fingerprint', unlock_card: 'Card', unlock_key: 'Mechanical key', unlock_face: 'Face recognition', unknown: 'Unidentified method' }

export default function UsageLogs({ record, user, isAdmin, onClose }) {
  const dialog = useRef(null)
  const [range, setRange] = useState(() => ({ start: localInput(new Date(Date.now() - 7 * 86400000)), end: localInput(new Date()) }))
  const [query, setQuery] = useState(() => ({ start: Math.floor(new Date(range.start).getTime() / 1000), end: Math.floor(new Date(range.end).getTime() / 1000), page: 1 }))
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState(record.passwordId ? 'key' : 'all')
  const [ascending, setAscending] = useState(false)

  useEffect(() => {
    if (!user || !isAdmin) return
    const element = dialog.current
    element.showModal()
    return () => element.close()
  }, [user, isAdmin])

  useEffect(() => {
    if (!user || !isAdmin) return
    let active = true
    Promise.resolve()
      .then(() => active ? httpsCallable(functions, 'manageAccess')({ action: 'logs', ...query }) : null)
      .then((response) => { if (active && response) setResult(response.data) })
      .catch((issue) => { if (active) setError(issue.message || 'Could not load unlock history.') })
      .finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [user, isAdmin, query])

  function loadQuery(next) {
    setBusy(true); setError(''); setResult(null); setQuery(next)
  }

  function applyRange(event) {
    event.preventDefault()
    const start = Math.floor(new Date(range.start).getTime() / 1000)
    const end = Math.floor(new Date(range.end).getTime() / 1000)
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start <= 0 || end <= start || end > Date.now() / 1000 + 60 || end - start > 90 * 86400) { setError('Select a past date range of up to 90 days.'); return }
    loadQuery({ start, end, page: 1 })
  }

  const matches = (entry) => !!record.passwordId && entry.method === 'unlock_temporary' && entry.passwordId === String(record.passwordId)
  const visible = (result?.records || []).filter((entry) => filter === 'all' || matches(entry)).sort((first, second) => ascending ? first.time - second.time : second.time - first.time)
  if (!user || !isAdmin) return null

  return <dialog ref={dialog} className="usage-dialog" aria-labelledby="usage-title" onCancel={onClose}>
    <div className="usage-heading"><div><div className="section-kicker">UNLOCK HISTORY</div><h2 id="usage-title">{record.name}</h2></div><button autoFocus className="icon-button" title="Close usage logs" aria-label="Close usage logs" onClick={onClose}><X size={18} /></button></div>
    <div className="banner warning" role="status"><AlertTriangle size={18} /><div><strong>{record.passwordId ? 'Tuya-reported events' : 'This key has no saved Tuya ID'}</strong><span>{record.passwordId ? 'Matching IDs are cloud reports. Offline events may be delayed or omit key IDs; this is not a complete usage count.' : 'Device events cannot be attributed to this key. Names and access times are not used to guess matches.'}</span></div></div>
    <form className="usage-range" onSubmit={applyRange}><label>From<input required type="datetime-local" value={range.start} onChange={(event) => setRange({ ...range, start: event.target.value })} /></label><label>Until<input required type="datetime-local" value={range.end} onChange={(event) => setRange({ ...range, end: event.target.value })} /></label><button className="text-button" disabled={busy}><RefreshCw size={15} /> Apply range</button></form>
    {error && <div className="banner error" role="alert"><div><strong>History unavailable</strong><span>{error}</span></div></div>}
    <div className="table-tools"><div className="tabs" role="tablist" aria-label="Usage log filter"><button role="tab" aria-selected={filter === 'key'} disabled={!record.passwordId} onClick={() => setFilter('key')}>Matching ID</button><button role="tab" aria-selected={filter === 'all'} onClick={() => setFilter('all')}>Device events</button></div><span className="table-count">{visible.length} on this page</span></div>
    <div className="table-wrap"><table><thead><tr><th><button className="sort-button" onClick={() => setAscending(!ascending)}>OCCURRED <ArrowDownUp size={12} /></button></th><th>METHOD</th><th>KEY LINK</th></tr></thead><tbody>{visible.map((entry) => <tr key={entry.id}><td>{formatDate(entry.time)}</td><td>{methods[entry.method] || entry.method.replace(/^unlock_/, '').replaceAll('_', ' ')}</td><td><span className={`status ${matches(entry) ? 'generated' : 'unknown'}`}>{matches(entry) ? 'Matching Tuya ID' : 'Unlinked'}</span></td></tr>)}</tbody></table>{!error && visible.length === 0 && <div className="empty"><div className="empty-icon"><History size={20} /></div><strong role="status">{busy ? 'Loading unlock history...' : filter === 'key' ? 'No matching events on this page' : 'No reported events on this page'}</strong></div>}</div>
    <div className="table-footer"><span>{result ? `${result.total} device records in range` : 'Tuya cloud history'} / local timezone</span><div className="row-actions"><button className="icon-button" title="Previous page" aria-label="Previous log page" disabled={busy || query.page === 1} onClick={() => loadQuery({ ...query, page: query.page - 1 })}><ChevronLeft size={16} /></button><span>Page {query.page}</span><button className="icon-button" title="Next page" aria-label="Next log page" disabled={busy || !result?.hasMore} onClick={() => loadQuery({ ...query, page: query.page + 1 })}><ChevronRight size={16} /></button></div></div>
  </dialog>
}