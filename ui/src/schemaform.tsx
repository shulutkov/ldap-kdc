import { ButtonHTMLAttributes, Fragment, ReactNode } from 'react'
import Form from '@rjsf/core'
import {
  ADDITIONAL_PROPERTY_FLAG,
  ArrayFieldItemButtonsTemplateProps,
  ArrayFieldItemTemplateProps,
  ArrayFieldTemplateProps,
  BaseInputTemplateProps,
  DescriptionFieldProps,
  FieldErrorProps,
  FieldHelpProps,
  FieldTemplateProps,
  IconButtonProps,
  ObjectFieldTemplateProps,
  RJSFSchema,
  UiSchema,
  ValidatorType,
  WrapIfAdditionalTemplateProps,
  ariaDescribedByIds,
  canExpand,
  getInputProps,
} from '@rjsf/utils'
import { Item } from './api'

// Forms built from the API's own OpenAPI document.
//
// The fields an operation accepts, their types, which are required, what they mean and what they
// default to all come from the schema the server generates from the Go types it decodes. The page
// keeps no second list of any of it, so a form cannot offer a field the API does not take or miss
// one it does.

// validator is deliberately not ajv. Ajv compiles every schema into a function with `new Function`,
// which the console's policy (script-src 'self', no 'unsafe-eval') refuses — and relaxing that
// policy on a page holding a session that can reset any password is not a trade worth making. The
// browser still enforces what the markup says (required fields, numbers), and the API decides the
// rest and says why.
export const validator: ValidatorType = {
  validateFormData: () => ({ errors: [], errorSchema: {} }),
  isValid: () => true,
  rawValidation: () => ({ errors: [] }),
}

type Schema = Record<string, unknown>

// labelFor turns an API field name into a label: "uidNumber" into "UID number". A string that is not
// a field name — a title already, or an attribute name somebody typed — is left as it is.
const ACRONYMS: Record<string, string> = { uid: 'UID', gid: 'GID', otp: 'OTP', ssh: 'SSH', ttl: 'TTL', dns: 'DNS', ok: 'OK', id: 'ID' }
const WORDS: Record<string, string> = { sn: 'Surname' }

export function labelFor(key: string): string {
  if (WORDS[key]) return WORDS[key]
  if (!/^[a-z][A-Za-z0-9]*$/.test(key)) return key
  const words = key.replace(/([A-Z])/g, ' $1').toLowerCase().split(' ').map((w) => ACRONYMS[w] ?? w)
  const text = words.join(' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
}

// FieldGroup is one titled section of a form: a heading and the field names under it, in the order
// they should appear. Naming a field the active schema does not have is not an error — a create and
// a patch of the same resource often differ by a few fields, and one grouping describes both; the
// name is simply absent from that form.
export type FieldGroup = { title: string; fields: string[] }

// uiSchemaFor names the top-level fields, sorts them into the sections `groups` describes (or, with
// no groups, puts `order`'s fields first), and applies a resource's few widget overrides. Everything
// else — types, requiredness, placeholders — follows the schema.
export function uiSchemaFor(schema: RJSFSchema, order: string[] = [], overrides: UiSchema = {}, groups?: FieldGroup[]): UiSchema {
  const props = (schema.properties ?? {}) as Record<string, Schema>
  const ui: UiSchema = {
    'ui:globalOptions': { orderable: false, copyable: false },
    'ui:submitButtonOptions': { norender: true },
  }
  for (const key of Object.keys(props)) {
    ui[key] = { 'ui:title': labelFor(key), ...((overrides[key] as object | undefined) ?? {}) }
  }
  // rjsf refuses an order that names a field the schema does not have, so the list is cut to the
  // fields this operation actually takes. A grouped form is ordered by its groups, field for field.
  const wanted = groups ? groups.flatMap((g) => g.fields) : order
  const ordered = wanted.filter((k) => k in props)
  if (ordered.length) ui['ui:order'] = [...ordered, '*']
  if (groups) ui['ui:groups'] = groups
  return ui
}

const isEmpty = (v: unknown): boolean =>
  v === undefined ||
  v === null ||
  v === '' ||
  (Array.isArray(v) && v.length === 0) ||
  (typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 0)

// fieldsOf picks, from an object the API returned, the fields an operation accepts.
export function fieldsOf(item: Item, schema: RJSFSchema): Item {
  return Object.fromEntries(Object.keys(schema.properties ?? {}).filter((k) => !isEmpty(item[k])).map((k) => [k, item[k]]))
}

// withoutEmpty drops what was left blank from a new object, so the API applies its own defaults
// rather than being told "empty" for every field nobody touched.
export function withoutEmpty(data: Item): Item {
  return Object.fromEntries(Object.entries(data).filter(([, v]) => !isEmpty(v)))
}

// changedFields is what a PATCH should carry: only what differs from what was loaded. The API reads
// an absent field as "leave it alone", so sending the whole form would be harmless only until two
// administrators edit one object at once. A field that was emptied is sent as its type's empty value
// — an empty list clears a list — and nothing is sent for one that was empty and stayed empty.
export function changedFields(initial: Item, current: Item, schema: RJSFSchema): Item {
  const out: Item = {}
  for (const [key, prop] of Object.entries((schema.properties ?? {}) as Record<string, Schema>)) {
    const before = initial[key]
    const after = current[key]
    if (isEmpty(before) && isEmpty(after)) continue
    if (JSON.stringify(before) === JSON.stringify(after)) continue
    if (!isEmpty(after)) {
      out[key] = after
      continue
    }
    const empty = prop.type === 'array' ? [] : prop.type === 'object' ? {} : prop.type === 'string' ? '' : undefined
    if (empty !== undefined) out[key] = empty
  }
  return out
}

// ---- templates: rjsf's structure, the catalog's vocabulary ----------------------------------------

const isAdditional = (schema: object) => ADDITIONAL_PROPERTY_FLAG in schema

function FieldTemplate(props: FieldTemplateProps) {
  const { id, label, children, errors, help, rawDescription, hidden, required, displayLabel, schema, registry } = props
  const { WrapIfAdditionalTemplate } = registry.templates
  if (hidden) return <div hidden>{children}</div>
  // A list or an object draws its own heading; wrapping it in a field would label it twice.
  const container = schema.type === 'object' || schema.type === 'array'
  return (
    <WrapIfAdditionalTemplate {...props}>
      {container ? (
        children
      ) : (
        <div className="field">
          {displayLabel && !isAdditional(schema) && (
            <label className="field-label" htmlFor={id}>
              {labelFor(label)}
              {required ? ' *' : ''}
            </label>
          )}
          {children}
          {displayLabel && rawDescription && <span className="hint">{rawDescription}</span>}
          {help}
          {errors}
        </div>
      )}
    </WrapIfAdditionalTemplate>
  )
}

function ObjectFieldTemplate({ properties, schema, uiSchema, formData, onAddProperty, disabled, readonly, title, fieldPathId, registry }: ObjectFieldTemplateProps) {
  const { AddButton } = registry.templates.ButtonTemplates
  const visible = properties.filter((p) => !p.hidden)
  const isMap = Boolean(schema.additionalProperties) && Object.keys(schema.properties ?? {}).length === 0
  if (isMap) {
    // A map — custom attributes — is a list of name and values pairs a person adds to.
    return (
      <div className="field">
        {title && <span className="field-label">{labelFor(title)}</span>}
        {typeof schema.description === 'string' && <span className="hint">{schema.description}</span>}
        {visible.length ? visible.map((p) => <Fragment key={p.name}>{p.content}</Fragment>) : <span className="hint">None yet.</span>}
        {canExpand(schema, uiSchema, formData) && (
          <div>
            <AddButton onClick={onAddProperty} disabled={disabled || readonly} registry={registry} />
          </div>
        )}
      </div>
    )
  }

  const isRoot = fieldPathId.path.length === 0

  if (!isRoot) {
    // A nested object — today, an array item's fields, like a capability's action and object — has
    // no heading of its own and lays out nothing itself: whatever wraps it already does (the array
    // item's row, in a `.form-row`), and a field-by-field list here would stack side by side what
    // belongs on one line.
    return <>{visible.map((p) => <Fragment key={p.name}>{p.content}</Fragment>)}</>
  }

  // The root object is the operation's whole body, laid out by whichever `ui:groups` it carries.
  const groups = uiSchema?.['ui:groups'] as FieldGroup[] | undefined
  if (!groups) return <div className="form-col">{visible.map((p) => <Fragment key={p.name}>{p.content}</Fragment>)}</div>

  // Sorted into the sections the resource named. A field the sections left out still has to be shown
  // — a schema grows a field before anyone remembers to place it — so it lands in a trailing,
  // unlabelled section rather than being silently dropped.
  const byName = new Map(visible.map((p) => [p.name, p]))
  const claimed = new Set<string>()
  const sections = groups
    .map((g) => ({
      title: g.title,
      fields: g.fields.map((f) => byName.get(f)).filter((p): p is (typeof visible)[number] => {
        if (!p) return false
        claimed.add(p.name)
        return true
      }),
    }))
    .filter((s) => s.fields.length > 0)
  const leftover = visible.filter((p) => !claimed.has(p.name))
  if (leftover.length) sections.push({ title: '', fields: leftover })

  return (
    <>
      {sections.map((s, i) => (
        <div className="panel" key={s.title || i}>
          {s.title && (
            <div className="panel-head">
              <span className="panel-title">{s.title}</span>
            </div>
          )}
          <div className="panel-body">
            <div className="form-col">{s.fields.map((p) => <Fragment key={p.name}>{p.content}</Fragment>)}</div>
          </div>
        </div>
      ))}
    </>
  )
}

function ArrayFieldTemplate({ items, canAdd, onAddClick, disabled, readonly, title, schema, registry }: ArrayFieldTemplateProps) {
  const { AddButton } = registry.templates.ButtonTemplates
  return (
    <div className="field">
      {title && !isAdditional(schema) && <span className="field-label">{labelFor(title)}</span>}
      {typeof schema.description === 'string' && <span className="hint">{schema.description}</span>}
      {items}
      {canAdd && (
        <div>
          <AddButton onClick={onAddClick} disabled={disabled || readonly} registry={registry} />
        </div>
      )}
    </div>
  )
}

function ArrayFieldItemTemplate({ children, buttonsProps, hasToolbar, registry }: ArrayFieldItemTemplateProps) {
  const { ArrayFieldItemButtonsTemplate } = registry.templates
  return (
    <div className="form-row">
      {children}
      {hasToolbar && <ArrayFieldItemButtonsTemplate {...buttonsProps} />}
    </div>
  )
}

function ArrayFieldItemButtonsTemplate({ hasRemove, onRemoveItem, disabled, readonly, registry }: ArrayFieldItemButtonsTemplateProps) {
  const { RemoveButton } = registry.templates.ButtonTemplates
  return hasRemove ? <RemoveButton onClick={onRemoveItem} disabled={disabled || readonly} registry={registry} /> : null
}

function WrapIfAdditionalTemplate({ children, schema, label, id, onKeyRenameBlur, onRemoveProperty, disabled, readonly, registry }: WrapIfAdditionalTemplateProps) {
  if (!isAdditional(schema)) return <>{children}</>
  const { RemoveButton } = registry.templates.ButtonTemplates
  return (
    <div className="form-row">
      <label className="field">
        <span className="field-label">Name</span>
        <input id={`${id}-key`} defaultValue={label} onBlur={onKeyRenameBlur} disabled={disabled || readonly} />
      </label>
      {children}
      <RemoveButton onClick={onRemoveProperty} disabled={disabled || readonly} registry={registry} />
    </div>
  )
}

// buttonAttrs keeps rjsf's own props off the DOM element.
function buttonAttrs(p: IconButtonProps): ButtonHTMLAttributes<HTMLButtonElement> {
  const { registry, uiSchema, iconType, icon, ...rest } = p
  void registry
  void uiSchema
  void iconType
  void icon
  return rest
}

const AddButton = (p: IconButtonProps) => (
  <button type="button" {...buttonAttrs(p)} className="secondary small">
    Add
  </button>
)

const RemoveButton = (p: IconButtonProps) => (
  <button type="button" {...buttonAttrs(p)} className="icon danger" title="Remove" aria-label="Remove">
    ✕
  </button>
)

const Nothing = () => null

// BaseInputTemplate is the plain input every text, number and date widget renders through. It is
// written here rather than taken from rjsf's core theme, which forwards its own props — the label
// among them — onto the element. It also reads the two things the schema says that rjsf does not: an
// example becomes the placeholder, and a password format hides what is typed.
function BaseInputTemplate(props: BaseInputTemplateProps) {
  const { id, htmlName, value, required, disabled, readonly, autofocus, placeholder, onChange, onChangeOverride, onBlur, onFocus, options, schema, type } = props
  const own = schema as Schema
  const input = getInputProps(schema, type, options)
  const password = own.format === 'password'
  const numeric = input.type === 'number' || input.type === 'integer'
  const example = own.example
  return (
    <input
      id={id}
      name={htmlName || id}
      {...input}
      type={password ? 'password' : input.type}
      autoComplete={password ? 'new-password' : undefined}
      value={numeric ? (value || value === 0 ? value : '') : (value ?? '')}
      required={required}
      disabled={disabled}
      readOnly={readonly}
      autoFocus={autofocus}
      placeholder={placeholder || (typeof example === 'string' || typeof example === 'number' ? String(example) : undefined)}
      onChange={onChangeOverride || ((e) => onChange(e.target.value === '' ? options.emptyValue : e.target.value))}
      onBlur={(e) => onBlur(id, e.target.value)}
      onFocus={(e) => onFocus(id, e.target.value)}
      aria-describedby={ariaDescribedByIds(id)}
    />
  )
}

const DescriptionFieldTemplate = ({ id, description }: DescriptionFieldProps) =>
  description ? (
    <span id={id} className="hint">
      {description}
    </span>
  ) : null

const FieldHelpTemplate = ({ help }: FieldHelpProps) => (help ? <span className="hint">{help}</span> : null)

const FieldErrorTemplate = ({ errors }: FieldErrorProps) =>
  errors && errors.length ? (
    <span className="hint">
      {errors.map((e, i) => (
        <Fragment key={i}>{e} </Fragment>
      ))}
    </span>
  ) : null

const templates = {
  FieldTemplate,
  ObjectFieldTemplate,
  ArrayFieldTemplate,
  ArrayFieldItemTemplate,
  ArrayFieldItemButtonsTemplate,
  WrapIfAdditionalTemplate,
  BaseInputTemplate,
  DescriptionFieldTemplate,
  FieldHelpTemplate,
  FieldErrorTemplate,
  TitleFieldTemplate: Nothing,
  ArrayFieldTitleTemplate: Nothing,
  ArrayFieldDescriptionTemplate: Nothing,
  ErrorListTemplate: Nothing,
  ButtonTemplates: { AddButton, RemoveButton, CopyButton: Nothing, MoveUpButton: Nothing, MoveDownButton: Nothing, SubmitButton: Nothing },
}

// SchemaForm renders one operation's body as a form. The buttons that submit it are the caller's,
// passed as children, so the form reads as part of the page rather than as a widget dropped into it.
export function SchemaForm({
  schema,
  uiSchema,
  formData,
  disabled,
  onChange,
  onSubmit,
  children,
}: {
  schema: RJSFSchema
  uiSchema: UiSchema
  formData: Item
  disabled?: boolean
  onChange: (data: Item) => void
  onSubmit: (data: Item) => void
  children: ReactNode
}) {
  return (
    <Form<Item, RJSFSchema>
      schema={schema}
      uiSchema={uiSchema}
      formData={formData}
      validator={validator}
      templates={templates}
      showErrorList={false}
      disabled={disabled}
      onChange={(e) => onChange((e.formData ?? {}) as Item)}
      onSubmit={(e) => onSubmit((e.formData ?? {}) as Item)}
    >
      {children}
    </Form>
  )
}
