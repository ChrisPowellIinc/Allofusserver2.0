package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ChrisPowellIinc/Allofusserver2.0/db"
	"github.com/ChrisPowellIinc/Allofusserver2.0/router"
	"github.com/stretchr/testify/assert"
)

func TestPingRoute(t *testing.T) {
	DB := db.MongoDB{}
	DB.Init()
	s := &Server{
		DB:     DB,
		Router: router.NewRouter(),
	}
	router := s.setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/signup", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "signup successful")
}
