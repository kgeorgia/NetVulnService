build:
	@go build -o ./server/VulnServer ./server/NetVulnServer.go
	@echo "NetVulnServer is done!"
	@go build -o ./client/VulnClient ./client/NetVulnClient.go
	@echo "NetVulnClient is done!"

test:
	@echo "TODO"

lint:
	@echo "TODO"

clean:
	@rm ./server/VulnServer
	@rm ./client/VulnClient
	@echo "all clean!"