package gtun

import (
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func CreateTun(name string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	ifce, err := water.New(config)
	if err != nil {
		return nil, err
	}
	return ifce, nil
}

func ConfigureTun(name string) error {
	tunDev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(tunDev)
	if err != nil {
		return err
	}

	loopDev, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(loopDev)
	if err != nil {
		return err
	}

	addr, _ := netlink.ParseAddr("10.0.0.1/24")
	netlink.AddrAdd(tunDev, addr)

	_, ip6Route, _ := net.ParseCIDR("240::1/128")
	route := netlink.Route{Dst: ip6Route, LinkIndex: tunDev.Attrs().Index}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return err
	}

	_, defaultdst, _ := net.ParseCIDR("0.0.0.0/0")
	route = netlink.Route{Dst: defaultdst, LinkIndex: tunDev.Attrs().Index}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return err
	}

	return nil
}
