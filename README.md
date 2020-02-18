# Certgen

Simply run `go run certgen.go` to get a self-signed certificate/key that you can use for your development environment.

Save the files somewhere and create appropriate environment variables, so you can `os.Getenv("CERT")` in your code.
