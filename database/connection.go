package database

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect() (*gorm.DB, error) {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5438")
	user := getEnv("DB_USER", "packetwatch")
	password := getEnv("DB_PASSWORD", "packetwatch123")
	dbname := getEnv("DB_NAME", "packetwatch")
	sslmode := getEnv("DB_SSLMODE", "disable")

	// PostgreSQL connection string
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=UTC",
		host, port, user, password, dbname, sslmode)

	// GORM config
	config := &gorm.Config(
		Logger: logger.Default.LogModel(logger.Info), // Collect Sql logs
	)

	// Connect to the database
	db, err := gorm.Open(postgres.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	// Setting connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Connection pool config
	sqlDB.SetMaxOpenConns(25)                   
	sqlDB.SetMaxIdleConns(5)                    // Max idle connection
	sqlDB.SetConnMaxLifetime(5 * time.Minute)   // Connection max lifetime

	// Database bağlantısını test et
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	fmt.Println("Database connection established")
	return db, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}