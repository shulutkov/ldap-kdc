import { Fragment, useEffect, useMemo, useState } from 'react'
import {
  ApiError,
  Item,
  SIGNED_OUT,
  Session,
  Stats,
  TOKEN,
  WhoAmI,
  api,
  describe,
  downloadKeytab,
  enc,
  signInWithKerberos,
  signInWithPassword,
  loadSpec,
  requestSchema,
} from './api'
import type { RJSFSchema, UiSchema } from '@rjsf/utils'
import { FieldGroup, SchemaForm, changedFields, fieldsOf, uiSchemaFor, withoutEmpty } from './schemaform'

// The console for the people who administer this directory. It is a view over the management API
// and nothing more: every change it makes is one request, made as the administrator who signed in
// and authorised by the server on its own. Hiding a button is a courtesy here, never a boundary.

type Kind = 'users' | 'groups' | 'principals' | 'dns' | 'trusts'
type Route = { page: 'overview' } | { page: 'list'; kind: Kind } | { page: 'item'; kind: Kind; key?: string }

const KINDS: Kind[] = ['users', 'groups', 'principals', 'dns', 'trusts']

function parseHash(): Route {
  const [kind, ...rest] = location.hash.replace(/^#\/?/, '').split('/')
  if (!KINDS.includes(kind as Kind)) return { page: 'overview' }
  if (!rest.length || rest[0] === '') return { page: 'list', kind: kind as Kind }
  if (rest[0] === '+new') return { page: 'item', kind: kind as Kind }
  return { page: 'item', kind: kind as Kind, key: rest.map(decodeURIComponent).join('/') }
}

const str = (v: unknown): string => (typeof v === 'string' ? v : v === undefined || v === null ? '' : JSON.stringify(v))
const yes = (v: unknown) => (v ? 'yes' : 'no')

// Resource is everything the generic list and editor need to know about one kind of object. The
// editor shows the fields the API accepts in a PATCH and nothing else: the API refuses unknown
// fields, so offering the rest would only be offering failures.
type Resource = {
  title: string
  collection: string
  columns: string[]
  cells: (v: Item) => React.ReactNode[]
  key: (v: Item) => string
  // load reads one object, and the fields its editor starts from.
  load?: (key: string, token: string) => Promise<Item>
  itemPath: (key: string) => string
  // patchPath is the operation an edit is sent to, as the OpenAPI document names it; none means the
  // object is not edited in place.
  patchPath?: string
  // order puts the fields a person looks for first at the top; the rest follow in the schema's order.
  // Ignored once groups is set — a grouped form is ordered by its groups instead.
  order?: string[]
  // groups sorts the form into titled sections instead of one flat list, for a resource with enough
  // fields that "everything in one box" stops being readable.
  groups?: FieldGroup[]
  // ui is the handful of per-field choices the schema cannot express.
  ui?: UiSchema
}

const principalKey = (v: Item) => `${str(v.name)}@${str(v.realm)}`

const RESOURCES: Record<Kind, Resource> = {
  users: {
    title: 'Users',
    collection: '/api/v1/users',
    columns: ['name', 'uid', 'mail', 'password', 'status'],
    cells: (v) => [
      <code>{str(v.name)}</code>,
      str(v.uidNumber),
      str(v.mail),
      v.hasPassword ? <span className="badge ok">set</span> : <span className="badge warn">none</span>,
      v.disabled ? <span className="badge bad">disabled</span> : <span className="badge ok">active</span>,
    ],
    key: (v) => str(v.name),
    itemPath: (k) => `/api/v1/users/${encodeURIComponent(k)}`,
    patchPath: '/api/v1/users/{name}',
    groups: [
      { title: 'Identity', fields: ['name', 'givenName', 'sn', 'mail'] },
      { title: 'Credentials', fields: ['password', 'forceChange', 'otpSecret'] },
      { title: 'POSIX account', fields: ['primaryGroup', 'otherGroups', 'uidNumber', 'loginShell', 'homeDirectory', 'sshKeys'] },
      { title: 'Kerberos', fields: ['aliases'] },
      { title: 'Access control', fields: ['disabled', 'capabilities'] },
      { title: 'Custom attributes', fields: ['customAttributes'] },
    ],
    ui: { otpSecret: { 'ui:widget': 'password' } },
    load: async (k, token) => (await api<{ user: Item }>(`/api/v1/users/${encodeURIComponent(k)}`, token)).user,
  },
  groups: {
    title: 'Groups',
    collection: '/api/v1/groups',
    columns: ['name', 'gid', 'description', 'capabilities'],
    cells: (v) => [
      <code>{str(v.name)}</code>,
      str(v.gidNumber),
      str(v.description),
      Array.isArray(v.capabilities) ? (v.capabilities as { action: string; object: string }[]).map((c) => `${c.action} ${c.object}`).join(', ') : '',
    ],
    key: (v) => str(v.name),
    itemPath: (k) => `/api/v1/groups/${encodeURIComponent(k)}`,
    patchPath: '/api/v1/groups/{name}',
    groups: [
      { title: 'Identity', fields: ['name', 'gidNumber', 'description'] },
      { title: 'Membership', fields: ['includeGroups'] },
      { title: 'Access control', fields: ['capabilities'] },
      { title: 'Custom attributes', fields: ['customAttributes'] },
    ],
    load: async (k, token) => (await api<{ group: Item }>(`/api/v1/groups/${encodeURIComponent(k)}`, token)).group,
  },
  principals: {
    title: 'Principals',
    collection: '/api/v1/principals',
    columns: ['name', 'account', 'kvno', 'pre-auth', 'status'],
    cells: (v) => [
      <code>{principalKey(v)}</code>,
      str(v.userName),
      str(v.kvno),
      yes(v.requiresPreAuth),
      !v.enabled ? <span className="badge bad">disabled</span> : v.lockedUntil ? <span className="badge warn">locked</span> : <span className="badge ok">enabled</span>,
    ],
    key: principalKey,
    itemPath: (k) => `/api/v1/principals/${enc(k)}`,
    patchPath: '/api/v1/principals/{name}',
    groups: [
      { title: 'Identity', fields: ['name', 'userName', 'aliases'] },
      { title: 'Credentials', fields: ['password'] },
      { title: 'Status', fields: ['enabled', 'expiresAt', 'passwordExpiresAt'] },
      { title: 'Ticket policy', fields: ['requiresPreAuth', 'allowForwardable', 'allowProxiable', 'allowRenewable', 'allowPostdate', 'maxTicketLife', 'maxRenewableLife'] },
      { title: 'Delegation', fields: ['okAsDelegate', 'okToAuthAsDelegate', 'allowedToDelegateTo', 'allowedToImpersonate'] },
    ],
    // Unlocking is its own button beside the form, not a box to tick and save.
    ui: { unlock: { 'ui:widget': 'hidden' } },
    load: async (k, token) => {
      const body = await api<{ principal: Item; maxTicketLife?: string; maxRenewableLife?: string }>(`/api/v1/principals/${enc(k)}`, token)
      return { ...body.principal, maxTicketLife: body.maxTicketLife ?? '', maxRenewableLife: body.maxRenewableLife ?? '' }
    },
  },
  dns: {
    title: 'DNS records',
    collection: '/api/v1/dns/records',
    columns: ['name', 'type', 'value', 'ttl'],
    cells: (v) => [<code>{str(v.name)}</code>, str(v.type), <code>{str(v.value)}</code>, str(v.ttl)],
    key: (v) => str(v.id),
    itemPath: (k) => `/api/v1/dns/records/${encodeURIComponent(k)}`,
    order: ['name', 'type', 'value', 'ttl'],
  },
  trusts: {
    title: 'Trusts',
    collection: '/api/v1/trusts',
    columns: ['remote realm', 'direction', 'transitive', 'status'],
    cells: (v) => [
      <code>{str(v.remoteRealm)}</code>,
      str(v.direction),
      yes(v.transitive),
      v.enabled ? <span className="badge ok">enabled</span> : <span className="badge bad">disabled</span>,
    ],
    key: (v) => str(v.remoteRealm),
    itemPath: (k) => `/api/v1/trusts/${encodeURIComponent(k)}`,
    patchPath: '/api/v1/trusts/{realm}',
    groups: [
      { title: 'Identity', fields: ['remoteRealm', 'direction'] },
      { title: 'Policy', fields: ['transitive', 'enabled'] },
      { title: 'Credentials', fields: ['password'] },
    ],
    load: async (k, token) => (await api<{ trust: Item }>(`/api/v1/trusts/${encodeURIComponent(k)}`, token)).trust,
  },
}

// listOf reads a collection. Each answers under its own name, so the one array in the body is it.
async function listOf(kind: Kind, token: string): Promise<Item[]> {
  const body = await api<Record<string, unknown>>(RESOURCES[kind].collection, token)
  const arr = Object.values(body).find(Array.isArray)
  return (arr as Item[] | undefined) ?? []
}

type Notice = { kind: 'ok' | 'bad'; text: string }

export default function App() {
  const [token, setTokenState] = useState<string | null>(() => sessionStorage.getItem(TOKEN))
  const [me, setMe] = useState<WhoAmI | null>(null)
  const [route, setRoute] = useState<Route>(parseHash)
  const [notice, setNotice] = useState<Notice | null>(null)

  const setToken = (t: string | null) => {
    if (t) sessionStorage.setItem(TOKEN, t)
    else sessionStorage.removeItem(TOKEN)
    setTokenState(t)
  }

  useEffect(() => {
    const onHash = () => {
      setRoute(parseHash())
      setNotice(null)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // Who am I, as the server sees it. Asked rather than read out of the token, and asked again on
  // every sign-in: a session the server no longer honours sends the person back to sign in.
  useEffect(() => {
    if (!token) {
      setMe(null)
      return
    }
    let cancelled = false
    api<WhoAmI>('/api/v1/auth/whoami', token)
      .then((id) => !cancelled && setMe(id))
      .catch((e) => {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 401) setToken(null)
        setNotice({ kind: 'bad', text: describe(e) })
      })
    return () => {
      cancelled = true
    }
  }, [token])

  const signedIn = (s: Session) => {
    sessionStorage.removeItem(SIGNED_OUT)
    setNotice(null)
    setToken(s.token)
  }

  // onFailure is what every page calls with an error: an ended session is sent back to sign in
  // rather than left looking at a page that can no longer do anything.
  const onFailure = (e: unknown) => {
    if (e instanceof ApiError && e.status === 401) setToken(null)
    setNotice({ kind: 'bad', text: describe(e) })
  }

  if (!token) {
    return (
      <>
        <header className="top">
          <span className="brand">ldap-kdc</span>
        </header>
        <main className="login">
          {notice && <div className={'notice ' + notice.kind}>{notice.text}</div>}
          <Login onSession={signedIn} />
        </main>
      </>
    )
  }

  return (
    <>
      <header className="top">
        <a className="brand" href="#/overview">
          ldap-kdc
        </a>
        <div className="right">
          {me && (
            <>
              <span className="who">{me.subject}</span>
              <span className="chip" title={me.expiresAt ? 'session ends ' + new Date(me.expiresAt).toLocaleString() : undefined}>
                {me.method}
              </span>
            </>
          )}
          <button
            className="secondary small"
            onClick={() => {
              sessionStorage.setItem(SIGNED_OUT, '1')
              setToken(null)
              setNotice({ kind: 'ok', text: 'You are signed out.' })
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <div className="frame">
        <aside className="side">
          <nav aria-label="Directory">
            <ul>
              <li>
                <a href="#/overview" className={route.page === 'overview' ? 'active' : ''}>
                  <span>Overview</span>
                </a>
              </li>
              <li className="side-label">Directory</li>
              {KINDS.map((k) => (
                <li key={k}>
                  <a href={`#/${k}`} className={route.page !== 'overview' && route.kind === k ? 'active' : ''}>
                    <span>{RESOURCES[k].title}</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </aside>
        <main>
          {notice && <div className={'notice ' + notice.kind}>{notice.text}</div>}
          {route.page === 'overview' ? (
            <Overview token={token} me={me} onFailure={onFailure} />
          ) : route.page === 'list' ? (
            <List key={route.kind} kind={route.kind} token={token} onFailure={onFailure} />
          ) : (
            <Editor
              key={route.kind + '/' + (route.key ?? '+new')}
              kind={route.kind}
              itemKey={route.key}
              token={token}
              onFailure={onFailure}
              onDone={(text) => {
                location.hash = `#/${route.kind}`
                setNotice({ kind: 'ok', text })
              }}
            />
          )}
        </main>
      </div>
    </>
  )
}

// Login offers the ticket first and the password second. Kerberos is tried once on arrival, and it
// either succeeds with nothing typed or fails quietly into the form — except right after Sign out,
// when it waits to be asked, or it would undo the button the person just pressed.
function Login({ onSession }: { onSession: (s: Session) => void }) {
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [kerberos, setKerberos] = useState<'trying' | 'failed' | 'idle'>(() => (sessionStorage.getItem(SIGNED_OUT) ? 'idle' : 'trying'))
  const [kerberosErr, setKerberosErr] = useState<string | null>(null)

  const tryKerberos = () => {
    setKerberos('trying')
    setKerberosErr(null)
    signInWithKerberos()
      .then(onSession)
      .catch((e) => {
        setKerberos('failed')
        // A plain challenge means the browser holds no ticket for this host or does not trust it —
        // the ordinary case, not an error worth a red box. Anything else is worth saying.
        if (!(e instanceof ApiError && (e.status === 401 || e.status === 404))) setKerberosErr(describe(e))
      })
  }

  useEffect(() => {
    if (kerberos === 'trying') tryKerberos()
    // Once, on arrival.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr(null)
    try {
      onSession(await signInWithPassword(login.trim(), password))
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 401 ? 'Incorrect login or password.' : describe(e))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <h1>Sign in</h1>
      <p className="muted">For directory administrators: accounts that may write the whole directory.</p>
      <div className="actions">
        <button disabled={kerberos === 'trying'} onClick={tryKerberos}>
          {kerberos === 'trying' ? 'Checking for a Kerberos ticket…' : 'Sign in with Kerberos'}
        </button>
        {kerberos === 'failed' && !kerberosErr && <span className="hint">No ticket this browser will offer for this host.</span>}
      </div>
      {kerberosErr && <div className="notice bad">{kerberosErr}</div>}
      <form onSubmit={submit} className="form-col">
        <label className="field">
          <span className="field-label">Login</span>
          <input autoComplete="username" value={login} onChange={(e) => setLogin(e.target.value)} placeholder="name or mail address" />
        </label>
        <label className="field">
          <span className="field-label">Password</span>
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <div className="actions">
          <button type="submit" disabled={busy || !login.trim() || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <span className="hint">A one-time code, where the account has one, goes at the end of the password.</span>
        </div>
      </form>
      {err && <div className="notice bad">{err}</div>}
    </div>
  )
}

function Overview({ token, me, onFailure }: { token: string; me: WhoAmI | null; onFailure: (e: unknown) => void }) {
  const [stats, setStats] = useState<Stats | null>(null)
  useEffect(() => {
    api<Stats>('/api/v1/stats', token).then(setStats).catch(onFailure)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  const card = (k: string, v: React.ReactNode, href?: string) => (
    <div className="tile" key={k}>
      <span className="hint">{k}</span>
      <span className="v">{href ? <a href={href}>{v}</a> : v}</span>
    </div>
  )

  return (
    <>
      <h1>Overview</h1>
      {!stats ? (
        <div className="empty">Loading…</div>
      ) : (
        <>
          <div className="tiles">
            {card('Realm', <code>{stats.realm}</code>)}
            {card('Users', stats.users.total, '#/users')}
            {card('Disabled', stats.users.disabled, '#/users')}
            {card('Without a password', stats.users.withoutPassword, '#/users')}
            {card('Groups', stats.groups, '#/groups')}
            {card('Principals', stats.principals, '#/principals')}
            {card('Trusts', stats.trusts, '#/trusts')}
            {card('Signed in as', me ? <code>{me.subject}</code> : '…')}
          </div>
          <h2>Encryption types</h2>
          <p className="hint">{stats.encTypes.join(', ')}</p>
          {stats.users.withoutPassword > 0 && (
            <p className="hint">
              An account without a password can neither bind over LDAP nor obtain a ticket until one is set.
            </p>
          )}
        </>
      )}
    </>
  )
}

function List({ kind, token, onFailure }: { kind: Kind; token: string; onFailure: (e: unknown) => void }) {
  const res = RESOURCES[kind]
  const [items, setItems] = useState<Item[] | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    listOf(kind, token).then(setItems).catch(onFailure)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, token])

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase()
    return (items ?? []).filter((v) => !f || JSON.stringify(v).toLowerCase().includes(f))
  }, [items, filter])

  return (
    <>
      <h1>
        {res.title}
        <div className="toolbar">
          <input placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <a href={`#/${kind}/+new`}>
            <button>New</button>
          </a>
        </div>
      </h1>
      {items === null ? (
        <div className="empty">Loading…</div>
      ) : shown.length === 0 ? (
        <div className="empty">{items.length ? 'Nothing matches the filter.' : 'Nothing here yet.'}</div>
      ) : (
        <div className="panel">
          <div className="panel-body tight table-wrap">
            <table>
              <thead>
                <tr>
                  {res.columns.map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map((v) => {
                  const key = res.key(v)
                  return (
                    <tr key={key} className="row" onClick={() => (location.hash = `#/${kind}/${key.split('/').map(encodeURIComponent).join('/')}`)}>
                      {res.cells(v).map((cell, i) => (
                        <td key={i}>{cell}</td>
                      ))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}


function Editor({
  kind,
  itemKey,
  token,
  onFailure,
  onDone,
}: {
  kind: Kind
  itemKey?: string
  token: string
  onFailure: (e: unknown) => void
  onDone: (text: string) => void
}) {
  const res = RESOURCES[kind]
  const creating = itemKey === undefined
  const [item, setItem] = useState<Item | null>(creating ? {} : null)
  const [schema, setSchema] = useState<RJSFSchema | null>(null)
  const [initial, setInitial] = useState<Item>({})
  const [data, setData] = useState<Item>({})
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    const load = creating
      ? Promise.resolve({})
      : res.load
        ? res.load(itemKey!, token)
        : listOf(kind, token).then((all) => {
            const found = all.find((v) => res.key(v) === itemKey)
            if (!found) throw new ApiError(404, 'no such object')
            return found
          })
    Promise.all([loadSpec(token), load])
      .then(([spec, v]) => {
        if (cancelled) return
        const path = creating ? res.collection : res.patchPath
        const body = path ? (requestSchema(spec, creating ? 'post' : 'patch', path) as RJSFSchema | null) : null
        setItem(v)
        setSchema(body)
        const start = body ? fieldsOf(v, body) : {}
        setInitial(start)
        setData(start)
      })
      .catch(onFailure)
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, itemKey, token])

  const uiSchema = useMemo(() => (schema ? uiSchemaFor(schema, res.order, res.ui, res.groups) : {}), [schema, res])

  const run = async (what: () => Promise<void>) => {
    setBusy(true)
    setErr(null)
    try {
      await what()
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) onFailure(e)
      else setErr(describe(e))
    } finally {
      setBusy(false)
    }
  }

  const save = (current: Item) =>
    run(async () => {
      if (creating) {
        await api(res.collection, token, { method: 'POST', body: JSON.stringify(withoutEmpty(current)) })
        onDone('Created.')
        return
      }
      const changes = changedFields(initial, current, schema!)
      if (Object.keys(changes).length === 0) {
        setErr('Nothing has changed.')
        return
      }
      await api(res.itemPath(itemKey!), token, { method: 'PATCH', body: JSON.stringify(changes) })
      onDone(`Saved ${itemKey}.`)
    })

  const remove = () =>
    run(async () => {
      if (!confirm(`Delete ${itemKey}? This cannot be undone.`)) return
      await api(res.itemPath(itemKey!), token, { method: 'DELETE' })
      onDone(`Deleted ${itemKey}.`)
    })

  const title = (
    <h1>
      <a href={`#/${kind}`}>{res.title}</a> / {creating ? <span className="muted">new</span> : <code>{itemKey}</code>}
    </h1>
  )

  if (item === null || (schema === null && (creating || res.patchPath))) {
    return (
      <>
        {title}
        <div className="empty">Loading…</div>
      </>
    )
  }

  return (
    <>
      {title}
      {!creating && <Facts kind={kind} item={item} />}
      {schema &&
        (() => {
          const form = (
            <SchemaForm schema={schema} uiSchema={uiSchema} formData={data} disabled={busy} onChange={setData} onSubmit={save}>
              <div className="actions">
                <button type="submit" disabled={busy}>
                  {creating ? 'Create' : 'Save'}
                </button>
                <span className="hint">{creating ? 'Fields left blank take the service’s defaults.' : 'Only what you change is sent.'}</span>
              </div>
            </SchemaForm>
          )
          // A grouped resource lays out its own titled panels, one per section; an ungrouped one
          // (a handful of fields, nothing to sort) gets the plain single box it always had.
          if (res.groups) return form
          return (
            <div className="panel">
              <div className="panel-head">
                <span className="panel-title">{creating ? 'New' : 'Settings'}</span>
              </div>
              <div className="panel-body">{form}</div>
            </div>
          )
        })()}
      {!creating && (
        <div className="actions">
          <Actions kind={kind} itemKey={itemKey!} item={item} token={token} run={run} onDone={onDone} />
          <button type="button" className="danger" disabled={busy} onClick={remove}>
            Delete
          </button>
        </div>
      )}
      {err && <div className="notice bad">{err}</div>}
    </>
  )
}

// Facts shows what is not edited here: identifiers, timestamps, credential state.
function Facts({ kind, item }: { kind: Kind; item: Item }) {
  const facts: [string, unknown][] =
    kind === 'users'
      ? [['id', item.id], ['password', item.hasPassword ? 'set' : 'none'], ['one-time code', item.hasOTP ? 'required' : 'not set'], ['created', item.createdAt], ['updated', item.updatedAt]]
      : kind === 'principals'
        ? [['kvno', item.kvno], ['account', item.userName || '—'], ['password set', item.passwordLastSet ?? '—'], ['password expires', item.passwordExpiresAt ?? '—'], ['failures', item.failCount], ['locked until', item.lockedUntil ?? '—']]
        : kind === 'groups'
          ? [['id', item.id], ['created', item.createdAt], ['updated', item.updatedAt]]
          : Object.entries(item).filter(([k]) => ['id', 'createdAt', 'updatedAt'].includes(k))
  return (
    <div className="panel">
      <dl className="kv panel-body">
        {facts.map(([k, v]) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd>{str(v)}</dd>
          </Fragment>
        ))}
      </dl>
    </div>
  )
}

// Actions are the operations that are not an edit of fields: credentials, keys and membership.
function Actions({
  kind,
  itemKey,
  item,
  token,
  run,
  onDone,
}: {
  kind: Kind
  itemKey: string
  item: Item
  token: string
  run: (what: () => Promise<void>) => Promise<void>
  onDone: (text: string) => void
}) {
  if (kind === 'users') {
    return (
      <button
        className="secondary"
        onClick={() =>
          run(async () => {
            const password = prompt(`New password for ${itemKey}. It is expired at once, so its owner chooses their own at the next sign-in.`)
            if (!password) return
            await api(`/api/v1/users/${encodeURIComponent(itemKey)}/password`, token, { method: 'POST', body: JSON.stringify({ password }) })
            onDone(`Password set for ${itemKey}; it must be changed at the next sign-in.`)
          })
        }
      >
        Set password
      </button>
    )
  }
  if (kind === 'principals') {
    return (
      <>
        <button className="secondary" onClick={() => run(() => downloadKeytab(itemKey, token))}>
          Download keytab
        </button>
        <button
          className="secondary"
          onClick={() =>
            run(async () => {
              if (!confirm(`Replace the keys of ${itemKey} with random ones? Keytabs issued before keep working only until their tickets expire.`)) return
              await api(`/api/v1/principals/${enc(itemKey)}/password`, token, { method: 'POST', body: JSON.stringify({ randomize: true }) })
              onDone(`${itemKey} re-keyed.`)
            })
          }
        >
          Randomize keys
        </button>
        {Boolean(item.lockedUntil) && (
          <button
            className="secondary"
            onClick={() =>
              run(async () => {
                await api(`/api/v1/principals/${enc(itemKey)}`, token, { method: 'PATCH', body: JSON.stringify({ unlock: true }) })
                onDone(`${itemKey} unlocked.`)
              })
            }
          >
            Unlock
          </button>
        )}
      </>
    )
  }
  return null
}
