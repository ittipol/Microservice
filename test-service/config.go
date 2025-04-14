package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents configuration for the app.
type Config struct {

	// Port to run the http server.
	AppPort int `yaml:"appPort"`

	RedisConfig RedisConfig `yaml:"redis"`
}

type RedisConfig struct {

	// Username to connect database.
	Username string `yaml:"username"`

	// Password to connect database.
	Password string `yaml:"password"`

	// Host to connect database.
	Host string `yaml:"host"`

	// Port to connect database.
	Port int `yaml:"port"`

	// Database to store value.
	Database int `yaml:"database"`
}

// loadConfig loads app config from YAML file.
func (c *Config) loadConfig(path string) {

	// Read the config file from the disk.
	f, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("os.ReadFile failed: %v", err)
	}

	// Convert the YAML config into a Go struct.
	err = yaml.Unmarshal(f, c)
	if err != nil {
		log.Fatalf("yaml.Unmarshal failed: %v", err)
	}
}
