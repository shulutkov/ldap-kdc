// @rjsf/core's index re-exports a test helper that imports rjsf's ajv validator. The console never
// calls that helper and the build drops it, but its import still has to resolve — to this, and not to
// ajv, which the console's content-security policy could not run anyway (see schemaform.tsx).
export default {}
