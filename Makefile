test:
	go test ./...

start-db:
	brew services start mongodb-community@4.2

stop-db:
	brew services stop mongodb-community@4.2