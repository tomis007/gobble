package gstack

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/songgao/water"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type GStack struct {
	stack            *stack.Stack
	connectionTokens chan struct{}
	loopback4        tcpip.Address
	loopback6        tcpip.Address
	drop6            bool
	drop4            bool
}

type TCPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *tcp.ForwarderRequest
}

type UDPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *udp.ForwarderRequest
}

type GStackOptions struct {
	Loopback  net.IP
	Loopback6 net.IP
	Drop6     bool
	Drop4     bool
	MaxConns  uint
}

func New(opts GStackOptions) (*GStack, error) {
	if opts.Loopback == nil {
		opts.Loopback = net.ParseIP("240.0.0.1")
	}
	if opts.Loopback6 == nil {
		opts.Loopback6 = net.ParseIP("240::1")
	}
	if opts.MaxConns == 0 {
		opts.MaxConns = 1024
	}

	return &GStack{
		connectionTokens: make(chan struct{}, opts.MaxConns),
		loopback4:        tcpip.AddrFromSlice(opts.Loopback.To4()),
		loopback6:        tcpip.AddrFromSlice(opts.Loopback6.To16()),
		drop4:            opts.Drop4,
		drop6:            opts.Drop6,
	}, nil
}

func (g *GStack) InitStack(tun *water.Interface) error {
	userstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				// TODO loopback/localhost connections via martian packets in gvisor?
				AllowExternalLoopbackTraffic: false,
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				// TODO loopback/localhost connections via martian packets in gvisor?
				AllowExternalLoopbackTraffic: false,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	mtu, err := rawfile.GetMTU(tun.Name())
	if err != nil {
		log.Fatal().Err(err)
	}
	log.Debug().Msg(fmt.Sprintf("tun name :%s", tun.Name()))

	// create a link endpoint based on the TUN device
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs:            []int{int(tun.ReadWriteCloser.(*os.File).Fd())},
		MTU:            mtu,
		EthernetHeader: tun.IsTAP(),
	})

	if err != nil {
		log.Fatal().Err(err)
	}

	// set rcvWnd to 0 for default buffer sizec
	tcpHandler := tcp.NewForwarder(userstack, 0, 1024, func(r *tcp.ForwarderRequest) {
		tcpConn := TCPConn{
			EndpointID: r.ID(),
			Request:    r,
		}
		g.HandleTCPConn(tcpConn)
	})

	udpHandler := udp.NewForwarder(userstack, func(r *udp.ForwarderRequest) {
		udpConn := UDPConn{
			EndpointID: r.ID(),
			Request:    r,
		}
		g.HandleUDPConn(udpConn)
	})

	userstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)
	userstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)

	nic := userstack.NextNICID()
	if err := userstack.CreateNIC(nic, endpoint); err != nil {
		log.Fatal().Msg(err.String())
	}
	userstack.SetPromiscuousMode(nic, true)
	userstack.SetSpoofing(nic, true)

	userstack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nic,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nic,
		},
	})
	g.stack = userstack

	return nil
}

func (g *GStack) dropCheck(address string) bool {
	if strings.Contains(address, ".") {
		return g.drop4
	} else if strings.Contains(address, ":") && g.drop6 {
		return g.drop6
	} else {
		log.Error().Msg(fmt.Sprintf("IP address not identified: %v", address))
		return true
	}
}

func (g *GStack) HandleUDPConn(newconn UDPConn) {
	g.connectionTokens <- struct{}{}
	log.Info().Msg(fmt.Sprintf("UDP -> %v:%v", newconn.EndpointID.LocalAddress, newconn.EndpointID.LocalPort))
	dAddr := fmt.Sprintf("%v:%d", newconn.EndpointID.LocalAddress, newconn.EndpointID.LocalPort)
	if g.dropCheck(newconn.EndpointID.LocalAddress.String()) {
		log.Info().Msg(fmt.Sprintf("UDP dropped connection: %s", dAddr))
		<-g.connectionTokens
		return
	}

	if newconn.EndpointID.LocalAddress == g.loopback4 {
		dAddr = fmt.Sprintf("127.0.0.1:%d", newconn.EndpointID.LocalPort)
	} else if newconn.EndpointID.LocalAddress == g.loopback6 {
		dAddr = fmt.Sprintf("[::1]:%d", newconn.EndpointID.LocalPort)
	}
	conn, err := net.Dial("udp", dAddr)
	deadline := time.Now().Add(time.Second)
	conn.SetDeadline(deadline)
	if err != nil {
		fmt.Printf("%v", err)
		<-g.connectionTokens
		return
	}

	var wq waiter.Queue
	ep, iperr := newconn.Request.CreateEndpoint(&wq)
	if iperr != nil {
		log.Error().Msg(iperr.String())
		<-g.connectionTokens
		return
	}
	gonetConn := gonet.NewUDPConn(&wq, ep)

	go func() {
		StartRelay(conn, gonetConn)
		<-g.connectionTokens
	}()
}

func (g *GStack) HandleTCPConn(newconn TCPConn) {
	g.connectionTokens <- struct{}{}
	log.Info().Msg(fmt.Sprintf("TCP -> %v:%v", newconn.EndpointID.LocalAddress, newconn.EndpointID.LocalPort))
	dAddr := fmt.Sprintf("%v:%d", newconn.EndpointID.LocalAddress, newconn.EndpointID.LocalPort)
	if g.dropCheck(newconn.EndpointID.LocalAddress.String()) {
		log.Info().Msg(fmt.Sprintf("TCP dropped connection: %s", dAddr))
		<-g.connectionTokens
		return
	}
	if newconn.EndpointID.LocalAddress == g.loopback4 {
		dAddr = fmt.Sprintf("127.0.0.1:%d", newconn.EndpointID.LocalPort)
	} else if newconn.EndpointID.LocalAddress == g.loopback6 {
		dAddr = fmt.Sprintf("[::1]:%d", newconn.EndpointID.LocalPort)
	}
	d := net.Dialer{Timeout: time.Second}
	log.Debug().Msg(fmt.Sprintf("daddr: %v", dAddr))
	conn, err := d.Dial("tcp", dAddr)
	if err != nil {
		log.Error().Err(err)
		newconn.Request.Complete(true)
		<-g.connectionTokens
		return
	}
	var wq waiter.Queue
	ep, iperr := newconn.Request.CreateEndpoint(&wq)
	if iperr != nil {
		log.Error().Err(err)
		newconn.Request.Complete(true)
		<-g.connectionTokens
		return
	}
	log.Debug().Msg("starting connection relay")
	gonetConn := gonet.NewTCPConn(&wq, ep)

	go func() {
		StartRelay(conn, gonetConn)
		<-g.connectionTokens
	}()
}

func relay(src net.Conn, dst net.Conn, stop chan error) {
	_, err := io.Copy(dst, src)

	dst.Close()
	src.Close()
	stop <- err
}

func StartRelay(src net.Conn, dst net.Conn) error {
	stop := make(chan error, 2)

	go relay(src, dst, stop)
	go relay(dst, src, stop)

	return <-stop
}
