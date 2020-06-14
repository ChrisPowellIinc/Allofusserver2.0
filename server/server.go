package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spankie/aou/db"
	"github.com/spankie/aou/router"
)

type Server struct {
	DB     db.DB
	Router *router.Router
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, data interface{}, status int) {
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
		// TODO: handle err
	}
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func (s *Server) defineRoutes(router *gin.Engine) {
	router.GET("/auth/signup", s.handleSignup())
	router.POST("/auth/login", s.handleLogin())
}

func (s *Server) setupRouter() *gin.Engine {
	r := gin.Default()
	s.defineRoutes(r)
	return r
}

func (s *Server) Start() {
	r := s.setupRouter()
	// r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Initializing the server in a goroutine so that
	// it won't block the graceful shutdown handling below
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}

// gracefulShutdown shutsdown the server gracefully
// when ctrl c is sent from the command line
func gracefulShutdown(s *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range quit {
			// sig is a ^C, handle it
			s.Shutdown(context.Background())
			fmt.Println("server shutdown successfully")
		}
	}()
}
