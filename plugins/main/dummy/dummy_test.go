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
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"net"
	"os/exec"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Dummy", func() {
	var (
		networkNS ns.NetNS
		command   *exec.Cmd
		environ   []string
	)

	BeforeEach(func() {
		command = exec.Command(pathToDummyPlugin)

		var err error
		networkNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		environ = []string{
			fmt.Sprintf("CNI_CONTAINERID=%s", "dummy"),
			fmt.Sprintf("CNI_NETNS=%s", networkNS.Path()),
			fmt.Sprintf("CNI_IFNAME=%s", "this is ignored"),
			fmt.Sprintf("CNI_ARGS=%s", "none"),
			fmt.Sprintf("CNI_PATH=%s", "/some/test/path"),
		}
		command.Stdin = strings.NewReader(`{ "name": "dummy-test", "cniVersion": "0.1.0", "addresses": ["169.254.169.254/32"] }`)
	})

	AfterEach(func() {
		Expect(networkNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(networkNS)).To(Succeed())
	})

	Context("when given a network namespace", func() {
		It("sets the dummy device to UP on ADD", func() {
			command.Env = append(environ, fmt.Sprintf("CNI_COMMAND=%s", "ADD"))

			session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())

			Eventually(session).Should(gbytes.Say(`{.*}`))
			Eventually(session).Should(gexec.Exit(0))

			var dummy *net.Interface
			err = networkNS.Do(func(ns.NetNS) error {
				var err error
				dummy, err = net.InterfaceByName("dummy0")
				return err
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(dummy.Flags & net.FlagUp).To(Equal(net.FlagUp))
		})

		It("allocates addresses on the dummy interface", func() {
			conf := `{
				"cniVersion": "0.3.1",
				"name": "mynet",
				"type": "dummy",
				"addresses": [
					"169.254.169.254/32"
				]
			}`

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       networkNS.Path(),
				IfName:      "eth0",
				StdinData:   []byte(conf),
				Args:        "",
			}

			r, raw, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })

			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(1))
			Expect(*result.Interfaces[0]).To(Equal(
				current.Interface{
					Name:    "dummy0",
					Sandbox: networkNS.Path(),
				}))

			Expect(len(result.IPs)).To(Equal(1))
			Expect(*result.IPs[0]).To(Equal(
				current.IPConfig{
					Version:   "4",
					Interface: current.Int(0),
					Address:   mustCIDR("169.254.169.254/32"),
				}))
		})

		It("can allocated IPs when chained", func() {
			conf := `{
				"cniVersion": "0.3.0",
				"name": "dummy-cni-test",
				"type": "dummy",
				"addresses": [
					"169.254.169.254/32"
				],
				"prevResult": {
					"interfaces": [
						{
							"name": "eth0",
							"sandbox": "/var/run/netns/test"
						}
					],
					"ips": [
						{
							"version": "4",
							"address": "10.0.0.2/24",
							"gateway": "10.0.0.1",
							"interface": 0
						}
					],
					"routes": []
				}
			}`

			args := &skel.CmdArgs{
				ContainerID: "dummy",
				Netns:       networkNS.Path(),
				IfName:      "eth0",
				StdinData:   []byte(conf),
				Args:        "",
			}

			r, raw, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })

			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Index(string(raw), "\"version\":")).Should(BeNumerically(">", 0))

			result, err := current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Interfaces)).To(Equal(2))
			Expect(*result.Interfaces[1]).To(Equal(
				current.Interface{
					Name:    "dummy0",
					Sandbox: networkNS.Path(),
				}))

			Expect(len(result.IPs)).To(Equal(2))
			Expect(*result.IPs[1]).To(Equal(
				current.IPConfig{
					Version:   "4",
					Interface: current.Int(1),
					Address:   mustCIDR("169.254.169.254/32"),
				}))
		})

		It("does not error on DEL", func() {
			command.Env = append(environ, fmt.Sprintf("CNI_COMMAND=%s", "DEL"))

			session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())

			Eventually(session).Should(gbytes.Say(``))
			Eventually(session).Should(gexec.Exit(0))
		})
	})
})

func mustCIDR(s string) net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	n.IP = ip
	if err != nil {
		Fail(err.Error())
	}

	return *n
}
