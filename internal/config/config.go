package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port           string
	DatabaseURL    string
	JWTSecret      string
	Environment    string
	RateLimit      RateLimitConfig
	InternalAPIKey string
	EncryptionKey  string
}

type RateLimitConfig struct {
	RequestsPerSecond int
	Burst             int
}

func Load() (*Config, error) {
	if os.Getenv("ENVIRONMENT") != "production" {
		if err := godotenv.Load(); err != nil {
			log.Println("⚠️ No se pudo cargar .env, usando variables de entorno del sistema")
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL es requerido")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET es requerido")
	}

	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	internalAPIKey := os.Getenv("INTERNAL_API_KEY")
	if internalAPIKey == "" {
		internalAPIKey = "api_key_de_prueba"
	}

	requestsPerSecond, _ := strconv.Atoi(os.Getenv("RATE_LIMIT_REQUESTS"))
	if requestsPerSecond == 0 {
		requestsPerSecond = 10
	}

	burst, _ := strconv.Atoi(os.Getenv("RATE_LIMIT_BURST"))
	if burst == 0 {
		burst = 20
	}

	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		encryptionKey = "ZGV2ZWxvcG1lbnRLZXkxMjM0NTY3ODkwMTIzNA=="
		log.Println("ENCRYPTION_KEY no configurado, usando clave de desarrollo. ¡No usar en producción!")
	}

	return &Config{
		Port:          port,
		DatabaseURL:   databaseURL,
		JWTSecret:     jwtSecret,
		Environment:   environment,
		RateLimit: RateLimitConfig{
			RequestsPerSecond: requestsPerSecond,
			Burst:             burst,
		},
		InternalAPIKey: internalAPIKey,
		EncryptionKey:  encryptionKey,
	}, nil
}