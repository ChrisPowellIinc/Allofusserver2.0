package main

import (
	"log"

	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/router"
	"github.com/ChrisPowellIinc/Allofusserver2.0/server"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("couldn't load env vars: %v", err)
	}

	DB := &db.MongoDB{}
	DB.Init()
	s := &server.Server{
		DB:     DB,
		Router: router.NewRouter(),
	}
	s.Start()
}
