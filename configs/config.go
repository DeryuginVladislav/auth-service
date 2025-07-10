package configs

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Db   DbConfig
	Auth AuthConfig
}

type DbConfig struct {
	Dsn string
}

type AuthConfig struct {
	Secret     string
	TTL        time.Duration
	WebhookURL string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()
	// if err != nil {
	// 	return nil, errors.New("error loading .env file")
	// }

	required := []string{"DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET", "ACCESS_TOKEN_TTL", "WEBHOOK_URL"}
	for _, v := range required {
		if os.Getenv(v) == "" {
			return nil, fmt.Errorf("missing required env variable: %s", v)
		}
	}

	ttl, err := strconv.Atoi(os.Getenv("ACCESS_TOKEN_TTL"))
	if err != nil {
		return nil, errors.New("invalid ACCESS_TOKEN_TTL")
	}

	dsn := fmt.Sprintf(
		"host=postgres port=5432 user=%s password=%s database=%s sslmode=disable",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	return &Config{
		Db: DbConfig{
			Dsn: dsn,
		},
		Auth: AuthConfig{
			Secret:     os.Getenv("JWT_SECRET"),
			TTL:        time.Minute * time.Duration(ttl),
			WebhookURL: os.Getenv("WEBHOOK_URL"),
		},
	}, nil
}
