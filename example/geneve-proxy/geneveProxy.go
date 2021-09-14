package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func handleConnection(conn net.PacketConn, peerIpAddress net.Addr, buf []byte) {
	// Remove Geneve layer
	packet := gopacket.NewPacket(buf, layers.LayerTypeGeneve, gopacket.NoCopy)
	// Extract IP Headers and Payload
	networkHeaders := packet.NetworkLayer().LayerContents()
	//fmt.Printf("%+X\n", networkHeaders)
	networkPayload := packet.NetworkLayer().LayerPayload()
	//fmt.Printf("%+X\n", networkPayload)
	modifiedPacket := append(networkHeaders, networkPayload...)

	// Open a raw socket to send new packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Printf("Fail to open Socket :%+v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	// Get Destination IP from the IP Header
	var array4byte [4]byte
	copy(array4byte[:], buf[56:60])
	sockAddress := syscall.SockaddrInet4{
		Port: 0,
		Addr: array4byte,
	}
	// Send the new packet to Ziti TProxy
	err = syscall.Sendto(fd, modifiedPacket, 0, &sockAddress)
	if err != nil {
		fmt.Printf("Failed to send modified packet to Socket: %+v\n", err)
	}
}

func main() {
	// Look for packet encapsulated in Geneve Protocol
	conn, err := net.ListenPacket("udp", ":6081")
	if err != nil {
		fmt.Printf("geneve decapsulation, exiting: %+v", err)
		panic(err)
	}
	defer conn.Close()

	for {
		buf := make([]byte, 2000)
		n, peerIpAddress, _ := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("error reading from buffer, exiting: %+v", err)
			panic(err)
		}
		go handleConnection(conn, peerIpAddress, buf[:n])
	}
}
