package main

import (
	"log"

	"github.com/pmohanj/golang-csrf-project/db"
	"github.com/pmohanj/golang-csrf-project/server"
	myjwt "github.com/pmohanj/golang-csrf-project/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	err := myjwt.InitJWT()
	if err != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(err)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server ig")
		log.Fatal(serverErr)
	}

}
