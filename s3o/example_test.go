package s3o_test

import (
	"log"
	"net/http"

	"github.com/Financial-Times/ft-s3o-go/s3o"
)

func ExampleHandler() {
	// create a "hello world" hander
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello world\n")) })

	// secure it with s3o
	handler = s3o.Handler(handler)

	// start our server
	log.Fatal(http.ListenAndServe(":8080", handler))
}
