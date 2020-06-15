package db

import (
	"fmt"
	"os"
	"time"

	"github.com/ChrisPowellIinc/Allofusserver2.0/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
)

// MongoDB implements the DB interface
type MongoDB struct {
	DB *mgo.Database
}

// Init sets up the mongodb instance
func (mdb *MongoDB) Init() {
	dburl := "mongodb://localhost:27017/allofus"
	dbname := "allofus"
	env := os.Getenv("GIN_MODE")
	if env == "release" {
		dbpassword := "allofus2020"
		dbuser := "allofus"
		dbname = "heroku_g3kd0627"
		dburl = fmt.Sprintf("mongodb://%s:%s@ds159274.mlab.com:59274/heroku_g3kd0627", dbuser, dbpassword)
	}
	DBSession, err := mgo.Dial(dburl)
	if err != nil {
		panic(errors.Wrap(err, "Unable to connect to Mongo database"))
	}
	mdb.DB = DBSession.DB(dbname)
}

// CreateUser creates a new user in the DB
func (mdb MongoDB) CreateUser(user models.User) (models.User, error) {
	user.CreatedAt = time.Now()
	err := mdb.DB.C("user").Insert(&user)
	return user, err
}

// FindUserByUsername finds a user by the username
func (mdb MongoDB) FindUserByUsername(username string) (models.User, error) {
	var user models.User
	err := mdb.DB.C("user").Find(bson.M{"username": username}).One(&user)
	return user, err
}
