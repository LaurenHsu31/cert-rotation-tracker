package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var staticFS embed.FS

// Handler serves the embedded single-page frontend. Because the whole UI is
// vendored (including Vue), it needs no build step and no internet at runtime —
// it runs fully offline on-prem.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
