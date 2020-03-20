// Copyright 2017-2020 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"
)

type PluginConf struct {
	types.NetConf

	// This is the previous result, when called in the context of a chained
	// plugin. Because this plugin supports multiple versions, we'll have to
	// parse this in two passes. If your plugin is not chained, this can be
	// removed (though you may wish to error if a non-chainable plugin is
	// chained.
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`

	IfName    string   `json:"ifname"`
	Addresses []string `json:"addresses"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result. Remove this if your plugin is not chained.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	// End previous result parsing

	if conf.IfName == "" {
		conf.IfName = "dummy0"
	}

	if conf.Addresses == nil || len(conf.Addresses) == 0 {
		return nil, fmt.Errorf("at least one address must be specified")
	}

	return &conf, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	var containerIPs []net.IP
	if conf.PrevResult != nil {
		containerIPs := make([]net.IP, 0, len(conf.PrevResult.IPs))
		// This is some sample code to generate the list of container-side IPs.
		// We're casting the prevResult to a 0.3.0 response, which can also include
		// host-side IPs (but doesn't when converted from a 0.2.0 response).
		//
		// You don't need this if you are writing an "originating" plugin.
		if conf.CNIVersion != "0.3.0" {
			for _, ip := range conf.PrevResult.IPs {
				containerIPs = append(containerIPs, ip.Address.IP)
			}
		} else {
			for _, ip := range conf.PrevResult.IPs {
				if ip.Interface == nil {
					continue
				}
				intIdx := *ip.Interface
				// Every IP is indexed in to the interfaces array, with "-1" standing
				// for an unknown interface (which we'll assume to be Container-side
				// Skip all IPs we know belong to an interface with the wrong name.
				if intIdx >= 0 && intIdx < len(conf.PrevResult.Interfaces) && conf.PrevResult.Interfaces[intIdx].Name != args.IfName {
					continue
				}
				containerIPs = append(containerIPs, ip.Address.IP)
			}
		}
	} else {
		conf.PrevResult = &current.Result{}
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		dummyLink, err := ensureLink(conf.IfName)
		if err != nil {
			return err
		}

		if conf.PrevResult.Interfaces == nil {
			conf.PrevResult.Interfaces = make([]*current.Interface, 0)
		}

		linkIndex := len(conf.PrevResult.Interfaces)
		conf.PrevResult.Interfaces = append(conf.PrevResult.Interfaces, &current.Interface{
			Name:    dummyLink.Attrs().Name,
			Mac:     dummyLink.Attrs().HardwareAddr.String(),
			Sandbox: args.Netns,
		})

		existingDummyAddrs, err := netlink.AddrList(dummyLink, syscall.AF_INET)
		if err != nil {
			return fmt.Errorf("unable to list IP addresses: %v", err)
		}

		for _, rawAddress := range conf.Addresses {
			addr, err := netlink.ParseAddr(rawAddress)
			if err != nil {
				return fmt.Errorf("unable to parse address: %v", err)
			}

			for _, cIP := range containerIPs {
				if cIP.Equal(addr.IP) {
					return fmt.Errorf("address %v already defined", addr.IP)
				}
			}

			if !isIpConfigured(existingDummyAddrs, addr) {
				err = netlink.AddrAdd(dummyLink, addr)
				if err != nil {
					return fmt.Errorf("unable to add address %s to interface %v: %v", addr, dummyLink.Attrs().Name, err)
				}

				if conf.PrevResult.IPs == nil {
					conf.PrevResult.IPs = make([]*current.IPConfig, 0)
				}
				conf.PrevResult.IPs = append(conf.PrevResult.IPs, &current.IPConfig{
					Version:   "4",
					Interface: current.Int(linkIndex),
					Address: net.IPNet{
						IP:   addr.IP,
						Mask: addr.Mask,
					},
				})
			}
		}

		err = netlink.LinkSetUp(dummyLink)
		if err != nil {
			return fmt.Errorf("unable to set link up: %v", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

func isIpConfigured(addrs []netlink.Addr, addr *netlink.Addr) bool {
	for _, existingAddr := range addrs {
		if existingAddr.Equal(*addr) {
			return true
		}
	}

	return false
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	// nothing to do here since dummy interface and IPs are assigned in the network namespace
	// which is destroyed upon delete

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("dummy"))
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func ensureLink(linkName string) (netlink.Link, error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return nil, fmt.Errorf("unable to lookup link %s by name: %v", linkName, err)
		}
	}

	if link == nil {
		la := netlink.NewLinkAttrs()
		la.Name = linkName
		link = &netlink.Dummy{LinkAttrs: la}
		err = netlink.LinkAdd(link)
		if err != nil {
			return nil, fmt.Errorf("could not add link %s: %v", la.Name, err)
		}

		return link, nil
	}

	return link, nil
}
