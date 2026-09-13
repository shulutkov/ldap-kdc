package api

import (
	"embed"
	"io/fs"
	"net/http"
)

// The console is a React application (ui/, Vite + TypeScript) whose BUILD is compiled into the
// binary and committed with the source: `go build` needs no node, and a service deployed where the
// internet is not still serves its pages from itself. `make ui` rebuilds the bundle when the
// sources change, and CI fails when the committed bundle is not what the sources build.
//
// The page is a courtesy, not a boundary. Everything it does it does through the API, as the
// administrator who signed in, and every one of those requests is authorised on its own.
//
//go:embed ui/dist
var consoleFiles embed.FS

// consoleCSP lets the page load itself and talk to this API, and nothing else. A value from the
// directory that turned out to contain markup is inert under it.
const consoleCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// consoleRoutes serves the console under /ui/ and sends the root there.
func (s *Server) consoleRoutes(mux *http.ServeMux) {
	if !s.cfg.UI {
		return
	}

	sub, err := fs.Sub(consoleFiles, "ui/dist")
	if err != nil {
		// The directory is embedded at build time; its absence would be a broken binary.
		panic("api: the console is not embedded: " + err.Error())
	}

	files := http.FileServerFS(sub)

	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", consoleCSP)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})))

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
}
