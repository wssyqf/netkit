// Package web 内嵌后台静态页面。
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html app.js pages.js webhook-form.js stats.js bigscreen.js ai.js pet.js style.css login.css pet.png
var staticFiles embed.FS

// Handler 返回后台静态页面的处理器。
func Handler() http.Handler {
	sub, _ := fs.Sub(staticFiles, ".")
	return http.StripPrefix("/", http.FileServer(http.FS(sub)))
}
