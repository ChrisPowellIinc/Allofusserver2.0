package main

import (
	"github.com/spankie/aou/db"
	"github.com/spankie/aou/router"
	"github.com/spankie/aou/server"
)

func main() {
	s := &server.Server{
		DB: db.DB{
			Users: make(db.Users, 0),
		},
		Router: router.NewRouter(),
	}
	s.Start()
}
