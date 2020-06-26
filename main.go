package main

import (
	"log"
	"os"

	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/router"
	"github.com/ChrisPowellIinc/Allofusserver2.0/server"
	"github.com/joho/godotenv"
)

func main() {
	env := os.Getenv("GIN_MODE")
	if env != "release" {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("couldn't load env vars: %v", err)
		}
	}

	DB := &db.MongoDB{}
	DB.Init()
	s := &server.Server{
		DB:     DB,
		Router: router.NewRouter(),
	}
	s.Start()
}
