package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	pbf "NetVulnService/proto"

	nmap "github.com/Ullaakut/nmap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

type ImplementedNetVulnServiceServer struct {
}

func (s *ImplementedNetVulnServiceServer) CheckVuln(c context.Context, request *pbf.CheckVulnRequest) (*pbf.CheckVulnResponse, error) {

	var tmpConvertPorts []string
	for _, value := range request.TcpPorts {
		tmpConvertPorts = append(tmpConvertPorts, strconv.Itoa(int(value)))
	}
	tcpPorts := strings.Join(tmpConvertPorts, ",")

	scanner, err := nmap.NewScanner(
		nmap.WithCustomArguments("-sV", "--script", "vulners"),
		nmap.WithTargets(request.Targets...),
		nmap.WithPorts(tcpPorts),
		nmap.WithContext(c),
	)
	if err != nil {
		grpclog.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		grpclog.Fatalf("unable to run nmap scan: %v", err)
	}

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)

	return &pbf.CheckVulnResponse{}, nil
}

func main() {
	listener, err := net.Listen("tcp", ":5300")
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}

	opts := []grpc.ServerOption{}
	grpcServer := grpc.NewServer(opts...)

	pbf.RegisterNetVulnServiceServer(grpcServer, &ImplementedNetVulnServiceServer{})
	if err := grpcServer.Serve(listener); err != nil {
		grpclog.Fatalf("failed to serve: %v", err)
	}
}
