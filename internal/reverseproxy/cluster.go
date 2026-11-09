package reverseproxy

import (
	"net/http"
	"net/http/httputil"

	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync/v2"

	"github.com/pgrok/pgrok/internal/tunnelauth"
)

// Proxy is a reverse proxy to a tunnel with its access policy.
type Proxy struct {
	*httputil.ReverseProxy
	// Policy is the access policy of the tunnel, nil means public.
	Policy *tunnelauth.Policy
}

// Cluster contains a list of proxies identified by their hosts.
type Cluster struct {
	proxies     map[string]*Proxy
	proxiesLock xsync.RBMutex
}

// NewCluster returns a new Cluster.
func NewCluster() *Cluster {
	return &Cluster{proxies: make(map[string]*Proxy)}
}

// Get returns the proxy by the given host. It returns a boolean to indicate
// whether such proxy exists.
func (c *Cluster) Get(host string) (*Proxy, bool) {
	t := c.proxiesLock.RLock()
	defer c.proxiesLock.RUnlock(t)

	proxy, ok := c.proxies[host]
	return proxy, ok
}

// Set atomically sets a proxy with the access policy for the given host. If the
// host is already taken, it tries the alternative host. It returns the actually
// used host or an error if both are taken.
func (c *Cluster) Set(host, alternative, forward string, policy *tunnelauth.Policy) (string, error) {
	c.proxiesLock.Lock()
	defer c.proxiesLock.Unlock()

	if _, exists := c.proxies[host]; !exists {
		c.proxies[host] = newProxy(forward, policy)
		return host, nil
	}
	if _, exists := c.proxies[alternative]; !exists {
		c.proxies[alternative] = newProxy(forward, policy)
		return alternative, nil
	}
	return "", errors.New("host and alternative are both taken")
}

func newProxy(forward string, policy *tunnelauth.Policy) *Proxy {
	return &Proxy{
		ReverseProxy: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.Out.URL.Scheme = "http"
				r.Out.URL.Host = forward
				r.SetXForwarded()
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(errors.Cause(err).Error()))
			},
		},
		Policy: policy,
	}
}

// Remove removes the proxy with given host from the cluster.
func (c *Cluster) Remove(host string) {
	c.proxiesLock.Lock()
	defer c.proxiesLock.Unlock()
	delete(c.proxies, host)
}
