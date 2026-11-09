package dynamicforward

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/flamego/flamego"
	"github.com/pkg/errors"
	"unknwon.dev/x/logx"
)

// UpstreamErrorHeader is set on the response when the client fails to reach the
// local service, so that pgrokd can tell it apart from a 502 returned by the
// local service itself and render a friendly error page.
const UpstreamErrorHeader = "X-Pgrok-Upstream-Error"

// Forward represents a dynamic forward rule.
type Forward struct {
	Prefix  string
	Address string
}

// New creates a new http.Handler for dynamic forwarding.
func New(logger *logx.Logger, defaultForwardAddr string, forwards ...Forward) (http.Handler, error) {
	defaultForwardURL, err := url.Parse(defaultForwardAddr)
	if err != nil {
		return nil, errors.Wrap(err, "parse default forward address")
	}

	defaultProxy := newProxy(logger, defaultForwardURL)
	proxies := make(map[string]*httputil.ReverseProxy)
	for _, forward := range forwards {
		forwardURL, err := url.Parse(forward.Address)
		if err != nil {
			return nil, errors.Wrapf(err, "parse forward address %q", forward.Address)
		}
		proxies[forward.Prefix] = newProxy(logger, forwardURL)
	}

	f := flamego.New()
	f.Use(func(c flamego.Context) {
		started := time.Now()
		c.Next()
		logger.Info("Forwarded request",
			"path", c.Request().URL.Path,
			"status", c.ResponseWriter().Status(),
			"duration", time.Since(started),
		)
	})
	f.Any("/{**}", func(w http.ResponseWriter, r *http.Request) {
		for prefix, proxy := range proxies {
			if strings.HasPrefix(r.URL.Path, prefix) {
				proxy.ServeHTTP(w, r)
				return
			}
		}
		defaultProxy.ServeHTTP(w, r)
	})
	return f, nil
}

// newProxy returns a reverse proxy to the target that marks its own failures
// to reach the target with UpstreamErrorHeader.
func newProxy(logger *logx.Logger, target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Failed to forward request", "path", r.URL.Path, "forwardTo", target.Host, "error", err)
		w.Header().Set(UpstreamErrorHeader, "1")
		w.WriteHeader(http.StatusBadGateway)
	}
	return proxy
}
