package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server Configuration
	Server ServerConfig `json:"server"`

	// Database Configuration
	Database DatabaseConfig `json:"database"`

	// Redis Configuration
	Redis RedisConfig `json:"redis"`

	// Packet Capture Configuration
	Capture CaptureConfig `json:"capture"`

	// Security Configuration
	Security SecurityConfig `json:"security"`

	// Monitoring Configuration
	Monitoring MonitoringConfig `json:"monitoring"`
}

type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	Environment  string        `json:"environment"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type DatabaseConfig struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	Username        string        `json:"username"`
	Password        string        `json:"password"`
	DatabaseName    string        `json:"database_name"`
	SSLMode         string        `json:"ssl_mode"`
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
}

type RedisConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	Password     string        `json:"password"`
	Database     int           `json:"database"`
	PoolSize     int           `json:"pool_size"`
	DialTimeout  time.Duration `json:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
}

type CaptureConfig struct {
	Interface   string        `json:"interface"`
	SnapLen     int           `json:"snap_len"`
	Promiscuous bool          `json:"promiscuous"`
	Timeout     time.Duration `json:"timeout"`
	BufferSize  int           `json:"buffer_size"`
	FilterPorts []int         `json:"filter_ports"`
	FilterIPs   []string      `json:"filter_ips"`
	EnableIPv6  bool          `json:"enable_ipv6"`
}

type SecurityConfig struct {
	JWTSecret      string        `json:"jwt_secret"`
	JWTExpiration  time.Duration `json:"jwt_expiration"`
	RateLimitRPS   int           `json:"rate_limit_rps"`
	RateLimitBurst int           `json:"rate_limit_burst"`
	CORSOrigins    []string      `json:"cors_origins"`
	TLSEnabled     bool          `json:"tls_enabled"`
	TLSCertPath    string        `json:"tls_cert_path"`
	TLSKeyPath     string        `json:"tls_key_path"`
}

type MonitoringConfig struct {
	PrometheusEnabled bool   `json:"prometheus_enabled"`
	PrometheusPath    string `json:"prometheus_path"`
	LogLevel          string `json:"log_level"`
	LogFormat         string `json:"log_format"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env file if it exists (for development)
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	config := &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvInt("DB_PORT", 5432),
			Username:        getEnv("DB_USERNAME", "packetwatch"),
			Password:        getEnv("DB_PASSWORD", "packetwatch123"),
			DatabaseName:    getEnv("DB_NAME", "packetwatch"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:         getEnv("REDIS_HOST", "localhost"),
			Port:         getEnvInt("REDIS_PORT", 6379),
			Password:     getEnv("REDIS_PASSWORD", ""),
			Database:     getEnvInt("REDIS_DB", 0),
			PoolSize:     getEnvInt("REDIS_POOL_SIZE", 10),
			DialTimeout:  getEnvDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:  getEnvDuration("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout: getEnvDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
		},
		Capture: CaptureConfig{
			Interface:   getEnv("CAPTURE_INTERFACE", "any"),
			SnapLen:     getEnvInt("CAPTURE_SNAP_LEN", 1600),
			Promiscuous: getEnvBool("CAPTURE_PROMISCUOUS", true),
			Timeout:     getEnvDuration("CAPTURE_TIMEOUT", 30*time.Second),
			BufferSize:  getEnvInt("CAPTURE_BUFFER_SIZE", 32*1024*1024), // 32MB
			FilterPorts: []int{80, 443, 22, 21, 25, 53, 993, 995},
			FilterIPs:   []string{},
			EnableIPv6:  getEnvBool("CAPTURE_ENABLE_IPV6", false),
		},
		Security: SecurityConfig{
			JWTSecret:      getEnv("JWT_SECRET", "packetwatch-dev-secret-change-in-production"),
			JWTExpiration:  getEnvDuration("JWT_EXPIRATION", 24*time.Hour),
			RateLimitRPS:   getEnvInt("RATE_LIMIT_RPS", 10),
			RateLimitBurst: getEnvInt("RATE_LIMIT_BURST", 20),
			CORSOrigins:    []string{"http://localhost:3000", "http://localhost:8080"},
			TLSEnabled:     getEnvBool("TLS_ENABLED", false),
			TLSCertPath:    getEnv("TLS_CERT_PATH", ""),
			TLSKeyPath:     getEnv("TLS_KEY_PATH", ""),
		},
		Monitoring: MonitoringConfig{
			PrometheusEnabled: getEnvBool("PROMETHEUS_ENABLED", true),
			PrometheusPath:    getEnv("PROMETHEUS_PATH", "/metrics"),
			LogLevel:          getEnv("LOG_LEVEL", "info"),
			LogFormat:         getEnv("LOG_FORMAT", "json"),
		},
	}

	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func (c *DatabaseConfig) DatabaseURL() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.Username, c.Password, c.DatabaseName, c.SSLMode)
}

func (c *RedisConfig) RedisURL() string {
	if c.Password != "" {
		return fmt.Sprintf("redis://:%s@%s:%d/%d", c.Password, c.Host, c.Port, c.Database)
	}
	return fmt.Sprintf("redis://%s:%d/%d", c.Host, c.Port, c.Database)
}

func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}
