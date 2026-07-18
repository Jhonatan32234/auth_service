package database

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	DB          *sql.DB
	dbURL       string
	dbMutex     sync.RWMutex
	isConnected bool
)

func Connect(databaseURL string) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	dbURL = databaseURL

	var err error
	DB, err = sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("error abriendo conexión: %w", err)
	}

	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(3)
	DB.SetConnMaxLifetime(5 * time.Minute)
	DB.SetConnMaxIdleTime(2 * time.Minute)

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("error haciendo ping: %w", err)
	}

	isConnected = true
	log.Println("Conexión a PostgreSQL establecida (Auth Service)")

	return nil
}

func Close() {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if DB != nil {
		DB.Close()
		DB = nil
		isConnected = false
	}
}