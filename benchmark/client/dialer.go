package main

import (
	"context"
	"fmt"
	"net"
//	"strconv"
)

type CustomDialer struct {
	intf string
	StartPort int
	EndPort	 int
}

//func (d *CustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
//	dialer := &net.Dialer{
//                LocalAddr: &net.TCPAddr{
//                    IP: net.ParseIP(d.intf),
//                    Port: 0,
//                },
//            }
//        return dialer.DialContext(ctx, network, address)
//}

func (d *CustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
    var reterr error
    for port := d.StartPort; port <= d.EndPort; port++ {
	dialer := &net.Dialer{
                LocalAddr: &net.TCPAddr{
                    IP: net.ParseIP(d.intf),
                    Port: port,
                },
            }
        conn, err := dialer.DialContext(ctx, network, address)
        if err == nil {
            return conn, nil
        } else {
	}
	reterr = err
    }
    return nil, reterr
}

func findNonLoopbackIP(name string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, intf := range interfaces {
		fmt.Println(intf.Name)
		if intf.Name == name {
			addrs, err := intf.Addrs()
			if err != nil {
				return "", err
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					return ipNet.IP.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("No non-loopback IP found")
}

func NewCustomDialer(name string, start , end int) (*CustomDialer, error) {
	ip, err := findNonLoopbackIP(name)
	if err != nil {
		return nil, err
	}
	return &CustomDialer{
		intf: ip,
		StartPort: start,
		EndPort: end,
	}, nil
}
