package main

import (
	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/router"
	"github.com/ChrisPowellIinc/Allofusserver2.0/server"
)

func main() {
	DB := &db.MongoDB{}
	DB.Init()
	s := &server.Server{
		DB:     DB,
		Router: router.NewRouter(),
	}
	s.Start()
}
