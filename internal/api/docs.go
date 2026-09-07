package api

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Swagger UI is embedded rather than fetched from a CDN: it is then there in an air-gapped
// network, it matches the binary it ships with, and the browser is not made to trust a third party
// with a page that holds an administrative token.
//
// The files are the swagger-ui-dist 5.32.15 release, stored compressed. They are minified bundles
// nobody reads, and 1.7 MB of them uncompressed would be 1.7 MB in every image; `make swagger-ui`
// fetches and compresses them again. The document they render is not a file at all: it is built
// from the route table when the service starts.
//
//go:embed swaggerui
var swaggerUI embed.FS

// docsModTime dates the documentation. The files cannot change once the binary is built, so one
// fixed instant is enough for a browser to cache them and revalidate cheaply.
var docsModTime = time.Now().UTC()

// docsRoutes serves the OpenAPI document and the Swagger UI that renders it.
//
// They are mounted outside the bearer token check on purpose: a browser cannot put an
// Authorization header on the address bar, so documentation behind the token would be unreachable
// by the only client that can use it. The document describes the surface, not the directory --
// there is nothing in it the README does not also say -- and every endpoint it describes stays
// behind the token. Swagger UI's Authorize button is where that token goes.
func (s *Server) docsRoutes(mux *http.ServeMux) {
	if !s.cfg.Docs {
		return
	}

	assets, err := fs.Sub(swaggerUI, "swaggerui")
	if err != nil {
		// The directory is embedded at build time; its absence would be a broken binary.
		panic("api: embedded documentation is missing: " + err.Error())
	}

	mux.HandleFunc("GET /api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.ServeContent(w, r, "openapi.json", docsModTime, bytes.NewReader(s.spec))
	})

	// Without the trailing slash a browser resolves the page's relative links one level too
	// high, and the assets come back as 404s.
	mux.HandleFunc("GET /api/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/docs/", http.StatusMovedPermanently)
	})

	mux.HandleFunc("GET /api/docs/{file...}", serveDocs(assets))
}

// serveDocs answers with one embedded file, decompressing it when the client did not ask for gzip.
func serveDocs(assets fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		if len(name) == 0 {
			name = "index.html"
		}

		body, compressed, err := readAsset(assets, name)
		if err != nil {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", assetContentType(name))

		if compressed {
			if acceptsGzip(r) {
				w.Header().Set("Content-Encoding", "gzip")
			} else if body, err = gunzip(body); err != nil {
				http.Error(w, "the embedded documentation could not be read",
					http.StatusInternalServerError)

				return
			}
		}

		http.ServeContent(w, r, name, docsModTime, bytes.NewReader(body))
	}
}

// readAsset reads a file, falling back to the compressed copy the large ones are stored as.
func readAsset(assets fs.FS, name string) (body []byte, compressed bool, err error) {
	if body, err = fs.ReadFile(assets, name); err == nil {
		return body, false, nil
	}

	body, err = fs.ReadFile(assets, name+".gz")

	return body, true, err
}

func acceptsGzip(r *http.Request) bool {
	for _, enc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(enc), ";")
		if strings.EqualFold(name, "gzip") {
			return true
		}
	}

	return false
}

func gunzip(body []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	return io.ReadAll(zr)
}

// assetContentType names the type from the extension rather than asking the operating system,
// which answers from a file that differs between machines and is missing in a scratch image.
func assetContentType(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".map", ".json":
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
