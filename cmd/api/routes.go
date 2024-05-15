package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

/*func (app *application) wrap(next http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		ctx := context.WithValue(r.Context(), "params", ps)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}*/

func (app *application) routes() http.Handler {
	// create a router mux
	mux := chi.NewRouter()

	mux.Use(middleware.Recoverer)
	mux.Use(app.enableCORS)

	mux.Post("/authenticate", app.authenticate)
	mux.Get("/refresh", app.refreshToken)
	mux.Get("/logout", app.logout)

	mux.Get("/status", app.statusHandler)

	//mux.Post("/signin", app.Signin)

	mux.Route("/works", func(mux chi.Router) {
		mux.Use(app.authRequiredWORKS)

		mux.Get("/dozvole1/{year}", app.getPermissions1)
		mux.Get("/planovi/{year}", app.getPlans)
	})

	return mux

}
