package db

import (
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
	DBSession, err := mgo.Dial("mongodb://localhost:27017/allofus")
	if err != nil {
		panic(errors.Wrap(err, "Unable to connect to Mongo database"))
	}
	mdb.DB = DBSession.DB("allofus")
}

// CreateUser creates a new user in the DB
func (mdb *MongoDB) CreateUser(user models.User) (models.User, error) {
	user.CreatedAt = time.Now()
	err := mdb.DB.C("user").Insert(&user)
	return user, err
}

// FindUserByUsername finds a user by the username
func (mdb *MongoDB) FindUserByUsername(username string) (models.User, error) {
	var user models.User
	err := mdb.DB.C("user").Find(bson.M{"username": username}).One(&user)
	return user, err
}

// FindUserByEmail finds a user by email
func (mdb *MongoDB) FindUserByEmail(email string) (models.User, error) {
	var user models.User
	err := mdb.DB.C("user").Find(bson.M{"email": email}).One(&user)
	mdb.DB.C("").Update()
	return user, err
}

// PutInBlackList puts blacklist into the blacklist collection
func (mdb *MongoDB) PutInBlackList(blacklist models.Blacklist) error {
	return mdb.DB.C("blacklist").Insert(&blacklist)
}
