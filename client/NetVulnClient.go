package main

import (
	pbf "NetVulnService/proto"
	"context"
	"os"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

func ParseArgs(args []string) ([]int32, []string) {
	var retTcpPorts []int32

	if len(args) < 3 {
		grpclog.Fatalf("Wrong number of arguments")
	}

	tmp := strings.Split(args[1], ",")
	for _, value := range tmp {
		conv, _ := strconv.Atoi(value)
		retTcpPorts = append(retTcpPorts, int32(conv))
	}

	return retTcpPorts, args[2:]
}

func main() {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}
	args := os.Args
	conn, err := grpc.Dial("127.0.0.1:5300", opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}

	defer conn.Close()

	client := pbf.NewNetVulnServiceClient(conn)

	tcpPorts, targets := ParseArgs(args)

	request := &pbf.CheckVulnRequest{
		TcpPorts: tcpPorts,
		Targets:  targets,
	}

	_, err = client.CheckVuln(context.Background(), request)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
}
