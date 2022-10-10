package server

import (
	"log"
	"net/http"

	"github.com/pmohanj/golang-csrf-project/middleware"
)

func StartServer(hostname, port string) error {
	host := hostname + ":" + port

	log.Println("Server starting at : ", host)

	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}
