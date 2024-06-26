package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/godror/godror"
	"github.com/tijanadmi/works_api/repository"
	"github.com/tijanadmi/works_api/repository/dbrepo"
)

const version = "1.0.0"

type config struct {
	port int
	env  string
	db   struct {
		dsn string
	}
	jwt struct {
		secret string
	}
}

type AppStatus struct {
	Status      string `json:"status"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
}

type application struct {
	config config
	logger *log.Logger
	DB     repository.DatabaseRepo
	//models       models.Models
	Domain       string
	auth         Auth
	JWTSecret    string
	JWTIssuer    string
	JWTAudience  string
	CookieDomain string
}

func main() {
	var cfg config
	var app application

	flag.IntVar(&cfg.port, "port", 4000, "Server port to listen on")
	flag.StringVar(&cfg.env, "env", "development", "Application environment (development|production")
	flag.StringVar(&cfg.db.dsn, "dsn", "", "Oracle connection string")
	flag.StringVar(&cfg.jwt.secret, "jwt-secret", "", "secret")
	flag.StringVar(&app.JWTSecret, "jwt-secret1", "", "signing secret")
	flag.StringVar(&app.JWTIssuer, "jwt-issuer", "", "signing issuer")
	flag.StringVar(&app.JWTAudience, "jwt-audience", "", "signing audience")
	flag.StringVar(&app.CookieDomain, "cookie-domain", "localhost", "cookie domain")
	flag.StringVar(&app.Domain, "domain", "example.com", "domain")

	flag.Parse()

	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime)

	db, err := openDB(cfg)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	logger.Println("Connected to database", cfg.port)

	app = application{
		config: cfg,
		logger: logger,
		DB:     &dbrepo.OracleDBRepo{DB: db},
		//models: models.NewModels(db),
		auth: Auth{
			Issuer:        app.JWTIssuer,
			Audience:      app.JWTAudience,
			Secret:        app.JWTSecret,
			TokenExpiry:   time.Minute * 15,
			RefreshExpiry: time.Hour * 24,
			CookiePath:    "/",
			CookieName:    "__Host-refresh_token",
			CookieDomain:  app.CookieDomain,
		},
	}
	logger.Println("Audience and Issuer", app.JWTAudience, app.JWTIssuer)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      app.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Println("Starting server on port", cfg.port)

	err = srv.ListenAndServe()
	if err != nil {
		log.Println(err)
	}

}

func openDB(cfg config) (*sql.DB, error) {
	db, err := sql.Open("godror", cfg.db.dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}
