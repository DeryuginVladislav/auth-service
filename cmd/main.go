package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/DeryuginVladislav/auth-service/configs"
	_ "github.com/DeryuginVladislav/auth-service/docs"
	"github.com/DeryuginVladislav/auth-service/internal"
	_ "github.com/lib/pq"
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	config, err := configs.LoadConfig()
	if err != nil {
		log.Fatal("faile load config")
	}

	router := http.NewServeMux()

	db, err := sql.Open("postgres", config.Db.Dsn)
	if err != nil {
		log.Fatalf("failed to open DB: %v", err)
	}
	for {
		err := db.Ping()
		if err == nil {
			break
		}
		log.Println("Waiting for database...")
		time.Sleep(2 * time.Second)
	}

	sessionRepository := internal.NewSessionReposytory(db)
	authService := internal.NewAuthService(sessionRepository, config)

	internal.NewAuthHandler(router, authService)

	// Swagger UI
	router.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	fmt.Println("Server is listening on port 8080")
	http.ListenAndServe(":8080", router)
}
