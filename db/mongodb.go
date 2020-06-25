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
func (mdb *MongoDB) CreateUser(user *models.User) (*models.User, error) {
	user.CreatedAt = time.Now()
	_, err := mdb.FindUserByEmail(user.Email)
	if err == nil {
		return user, ValidationError{Field: "email", Message: "already in use"}
	}
	_, err = mdb.FindUserByUsername(user.Username)
	if err == nil {
		return user, ValidationError{Field: "username", Message: "already in use"}
	}
	_, err = mdb.FindUserByPhone(user.Phone)
	if err == nil {
		return user, ValidationError{Field: "phone", Message: "already in use"}
	}
	err = mdb.DB.C("user").Insert(&user)
	return user, err
}

// FindUserByUsername finds a user by the username
func (mdb *MongoDB) FindUserByUsername(username string) (*models.User, error) {
	var user *models.User
	err := mdb.DB.C("user").Find(bson.M{"username": username}).One(user)
	return user, err
}

// FindUserByEmail finds a user by the email
func (mdb MongoDB) FindUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := mdb.DB.C("user").Find(bson.M{"email": email}).One(user)
	if user.Status != "active" {
		return &models.User{}, errors.New("user not activated")
	}
	return user, err
}

// FindUserByPhone finds a user by the phone
func (mdb MongoDB) FindUserByPhone(phone string) (*models.User, error) {
	user := &models.User{}
	err := mdb.DB.C("user").Find(bson.M{"phone": phone}).One(&user)
	return user, err
}

// UpdateUser updates the src document to dest in the user collection
func (mdb *MongoDB) UpdateUser(src *models.User, dest *models.User) error {
	return mdb.DB.C("user").Update(src, dest)
}

// AddToBlackList puts blacklist into the blacklist collection
func (mdb *MongoDB) AddToBlackList(blacklist *models.Blacklist) error {
	return mdb.DB.C("blacklist").Insert(blacklist)
}
