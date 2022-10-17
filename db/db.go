package db

import (
	"errors"

	"github.com/pmohanj/golang-csrf-project/db/models"
)

var users = map[string]models.User{}

func InitDB() {

}

func StoreUser(username, password, role string) (uuid string, err error) {

}

func DeleteUser() {

}

func FetchUserById() {

}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("User not found that matches given username")
}

func StoreRefreshToken() {

}

func DeleteRefreshToken() {

}

func CheckRefreshToken() bool {

}

func LogUserInt() (models.User, string, error) {

}

func generateBcryptHash() (string, error) {

}

func checkPassordAgainstHash() error {

}
