package web

import (
	"net/http"
	"time"

	"github.com/flamego/flamego"
	"unknwon.dev/x/logx"

	"github.com/pgrok/pgrok/internal/tunnels"
)

func getUserInfo(c *Context, r flamego.Render) {
	r.JSON(http.StatusOK, map[string]any{
		"displayName": c.Principal.DisplayName,
		"token":       c.Principal.Token,
		"url":         c.Config.Proxy.Scheme + "://" + c.Principal.Subdomain + "." + c.Config.Proxy.Domain,
		"isAdmin":     c.IsAdmin(),
	})
}

// getIdentityProvider reports the configured identity provider so the sign-in
// page can render the correct "Continue with ..." action.
func getIdentityProvider(c *Context, r flamego.Render) {
	if c.Config.IdentityProvider == nil {
		r.JSON(http.StatusInternalServerError, map[string]string{
			"error": "No identity provider is configured, please ask your admin to configure an identity provider.",
		})
		return
	}
	r.JSON(http.StatusOK, map[string]string{
		"displayName": c.Config.IdentityProvider.DisplayName,
		"authURL":     "/-/oidc/auth",
	})
}

type tunnelInfo struct {
	ID          string    `json:"id"`
	Protocol    string    `json:"protocol"`
	URL         string    `json:"url"`
	RemoteAddr  string    `json:"remoteAddr"`
	ConnectedAt time.Time `json:"connectedAt"`
}

// getTunnels lists the active tunnels of the signed-in principal.
func getTunnels(registry *tunnels.Registry) flamego.Handler {
	return func(c *Context, r flamego.Render) {
		list := registry.ListByPrincipal(c.Principal.ID)
		resp := make([]tunnelInfo, 0, len(list))
		for _, t := range list {
			resp = append(resp, tunnelInfo{
				ID:          t.ID,
				Protocol:    t.Protocol,
				URL:         t.URL,
				RemoteAddr:  t.RemoteAddr,
				ConnectedAt: t.ConnectedAt,
			})
		}
		r.JSON(http.StatusOK, resp)
	}
}

// deleteTunnel closes an active tunnel of the signed-in principal by
// disconnecting its client. Tunnels of other principals are reported as not
// found.
func deleteTunnel(logger *logx.Logger, registry *tunnels.Registry) flamego.Handler {
	return func(c *Context, r flamego.Render) {
		t, ok := registry.Get(c.Param("id"))
		if !ok || t.PrincipalID != c.Principal.ID {
			r.JSON(http.StatusNotFound, map[string]string{
				"error": "Tunnel not found",
			})
			return
		}

		// The connection may already be going away on its own, in which case the
		// error is benign because the tunnel ends either way.
		if err := t.Close(); err != nil {
			logger.Debug("Failed to close tunnel", "id", t.ID, "error", err)
		}
		c.ResponseWriter().WriteHeader(http.StatusNoContent)
	}
}
