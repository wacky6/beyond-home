package web

import (
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	frontendBuild "github.com/wacky6/beyond-home/web/build"
)

type ErrorPage int

const (
	ErrorServiceUnavailable ErrorPage = iota
)

const devServerURL = "http://localhost:8025/"

// Only one of the following will be valid, based on whether we're running in
// development environment.
var devServerProxy *httputil.ReverseProxy
var httpFileServer http.Handler

func init() {
	if _, err := os.Stat(".git"); !os.IsNotExist(err) {
		log.Printf("WARN: Found .git, assuming dev environment.")
		log.Printf("WARN: Serving front-end resources from dev-server: %v", devServerURL)
		url, err := url.Parse(devServerURL)
		if err != nil {
			log.Fatalf("Dev-server URL is invalid: %v", devServerURL)
		}
		devServerProxy = httputil.NewSingleHostReverseProxy(url)
	} else {
		log.Printf("Serving production frontend.")
		httpFileServer = http.FileServer(http.FS(frontendBuild.WebFs))
	}
}

// Serve path to http.ResponseWriter.
func Serve(w http.ResponseWriter, req *http.Request) {
	if devServerProxy != nil {
		devServerProxy.ServeHTTP(w, req)
		return
	}
	if httpFileServer != nil {
		httpFileServer.ServeHTTP(w, req)
		return
	}

	w.Header().Set("Content-Type", mime.TypeByExtension(".txt"))
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("ERROR: BeyondHome internal error: No valid front-end serving source."))
}

func ServeError(error_page ErrorPage, w http.ResponseWriter) {
	// Request path rewrite.
	var actualPath string
	switch error_page {
	case ErrorServiceUnavailable:
		actualPath = "index_503.html"
	}

	fakeReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost/%s", actualPath), strings.NewReader(""))
	if err != nil {
		log.Fatalf("Failed to create fake http request for frontend serving")
	}

	Serve(w, fakeReq)
}
