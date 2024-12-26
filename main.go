package main

import (
	"fmt"
	"go-file-storage-project/routes"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/upload", routes.UploadFile).Methods("POST")
	r.HandleFunc("/download", routes.DownloadFile).Methods("GET")

	fmt.Println("server started...")

	log.Fatal(http.ListenAndServe(":8080", r))

}
