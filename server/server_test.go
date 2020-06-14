package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spankie/aou/db"
	"github.com/spankie/aou/router"
	"github.com/stretchr/testify/assert"
)

func TestPingRoute(t *testing.T) {
	s := &Server{
		DB: db.DB{
			Users: make(db.Users, 0),
		},
		Router: router.NewRouter(),
	}
	router := s.setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/signup", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "signup successful")
}
