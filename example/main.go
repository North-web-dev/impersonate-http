package main

import (
	"fmt"
	"io"
	"log"

	imp "github.com/North-web-dev/impersonate-http"
)

func main() {
	client := imp.New(imp.Chrome)
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status %s\n%s\n", resp.Status, body)
}
