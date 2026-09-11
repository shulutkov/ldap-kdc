package oidc

import "html/template"

// The two pages this provider renders. They are plain and self-contained on purpose: a sign-in
// page that pulls a stylesheet or a font from somewhere else is a sign-in page whose appearance —
// and whose availability — belongs to a third party.
var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
 :root { color-scheme: light dark; }
 body { font: 16px/1.5 system-ui, sans-serif; margin: 0; display: grid; place-items: center;
        min-height: 100vh; background: Canvas; color: CanvasText; }
 form { width: min(22rem, 92vw); display: grid; gap: .75rem; padding: 2rem 1rem; }
 h1 { font-size: 1.1rem; font-weight: 600; margin: 0 0 .5rem; }
 p.for { margin: 0 0 1rem; opacity: .7; font-size: .9rem; }
 label { display: grid; gap: .25rem; font-size: .85rem; }
 input { font: inherit; padding: .5rem .6rem; border: 1px solid GrayText; border-radius: .4rem;
         background: Field; color: FieldText; }
 button { font: inherit; padding: .55rem; border: 0; border-radius: .4rem; cursor: pointer;
          background: Highlight; color: HighlightText; }
 .problem { margin: 0; padding: .5rem .6rem; border-radius: .4rem; font-size: .9rem;
            background: color-mix(in srgb, Mark 40%, Canvas); }
</style></head><body>
<form method="post" action="{{.Action}}">
  <h1>Sign in</h1>
  <p class="for">to continue to {{.Client}}</p>
  {{if .Problem}}<p class="problem">{{.Problem}}</p>{{end}}
  <input type="hidden" name="req" value="{{.Request}}">
  <label>Login<input name="login" autocomplete="username" autofocus required></label>
  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
</body></html>
`))

var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot sign in</title>
<style>
 :root { color-scheme: light dark; }
 body { font: 16px/1.5 system-ui, sans-serif; margin: 0; display: grid; place-items: center;
        min-height: 100vh; background: Canvas; color: CanvasText; }
 main { width: min(32rem, 92vw); padding: 2rem 1rem; }
 h1 { font-size: 1.1rem; font-weight: 600; }
 code { word-break: break-all; }
</style></head><body>
<main>
  <h1>{{.Message}}</h1>
  {{if .Detail}}<p><code>{{.Detail}}</code></p>{{end}}
</main>
</body></html>
`))
