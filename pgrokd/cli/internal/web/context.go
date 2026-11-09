package web

import (
	"mime"
	"net/http"
	"slices"

	"github.com/flamego/flamego"
	"github.com/flamego/session"

	"github.com/pgrok/pgrok/internal/conf"
	"github.com/pgrok/pgrok/internal/database"
)

// Context is the request-scoped context shared by the web and API handlers,
// modeled after the *context.Context that Gogs threads through its routers. It
// carries the server config and, when authenticated, the current principal.
type Context struct {
	flamego.Context

	Config    *conf.Config
	Session   session.Session
	Principal *database.Principal // The authenticated principal, or nil when signed out.
}

// Authenticated reports whether the request has an authenticated principal.
func (c *Context) Authenticated() bool {
	return c.Principal != nil
}

// IsAdmin reports whether the authenticated principal is listed in the "admins"
// config option.
func (c *Context) IsAdmin() bool {
	return c.Authenticated() && slices.Contains(c.Config.Admins, c.Principal.Identifier)
}

// contexter builds and injects a *Context for every request, loading the
// signed-in principal from the session (best effort) so downstream handlers can
// rely on c.Principal / c.IsSignedIn.
func contexter(config *conf.Config, db *database.DB) flamego.Handler {
	return func(ctx flamego.Context, s session.Session) {
		c := &Context{
			Context: ctx,
			Config:  config,
			Session: s,
		}

		if userID, ok := s.Get("userID").(int64); ok && userID > 0 {
			// Blocked principals are treated as signed out for as long as they stay
			// blocked.
			if principal, err := db.GetPrincipalByID(ctx.Request().Context(), userID); err == nil && !principal.Blocked {
				c.Principal = principal
			}
		}

		ctx.Map(c)
	}
}

// authenticate aborts unauthenticated requests with 401.
func authenticate(c *Context) {
	if !c.Authenticated() {
		c.ResponseWriter().WriteHeader(http.StatusUnauthorized)
	}
}

// requireAdmin aborts unauthenticated requests with 401 and requests from
// non-admins with 403.
func requireAdmin(c *Context) {
	if !c.Authenticated() {
		c.ResponseWriter().WriteHeader(http.StatusUnauthorized)
		return
	}
	if !c.IsAdmin() {
		c.ResponseWriter().WriteHeader(http.StatusForbidden)
	}
}

// requireJSON aborts requests whose body is not declared as JSON with 415. A
// cross-origin page cannot send such a request without a CORS preflight, which
// pgrokd never approves, so this guards state-changing endpoints against
// cross-site request forgery. The session cookie's SameSite=Lax alone is not
// enough because tunnel hosts are on the same site as the dashboard.
func requireJSON(c *Context) {
	mediaType, _, _ := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
	if mediaType != "application/json" {
		c.ResponseWriter().WriteHeader(http.StatusUnsupportedMediaType)
	}
}
