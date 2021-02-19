package main

import (
	harvester "github.com/belgaied2/docker-machine-driver-harvester/drivers"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(harvester.NewDriver("", ""))

}

// func main() {
// 	d := harvester.NewDriver("", "")

// 	hostIP, err := d.GetSSHHostname()
// 	println("IP Address of Host: ", hostIP)

// 	sshPort, err := d.GetSSHPort()
// 	println("SSH Port is :", sshPort)

// 	if err != nil {
// 		println(err)
// 	}

// }
