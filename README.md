# Harvester Driver for Docker Machine

This repository is a Harvester Driver for Docker Machine. It uses the Kubernetes API underlying Harvester (since Harvester does not yet an official API) in order manage VM lifecycle.

The Create() operation will create an Object VirtualMachine with some labels for Harvester.

At the moment, integration with Docker is not perfect. Using `docker-machine create -d harvester` is run, a VM is successfully created in Harvester, and it is visible using `docker-machine ls`. However, some lifecycle steps are still buggy.

Also, since my knowledge in Harvester and the bridge network is lacking, I implemented NodePort services to connect to the VM from docker-machine.

## Warning
This repo is not yet well documented and not fully functional, it is designed to be a POC for the Node Driver feature for Harvester in Rancher.

## Installation
In order to use this [Docker Machine](https://docs.docker.com/machine/install-machine/#install-docker-machine) plugin, you need to have `docker-machine` already installed.

You can then download the binary for the Harvester Driver from the [Releases page](https://github.com/belgaied2/docker-machine-driver-harvester/releases). This binarz file `docker-machine-driver-harvester` needs to be placed in your `$PATH` for instance `/usr/local/bin/`.
Now, the file needs to be executable
```
sudo chmod +x /usr/local/bin/docker-machine-driver-harvester
```
Check the installation by running and understand how to create VMs in Harvester using `docker-machine`:
```
docker-machine create -d harvester --help

Usage: docker-machine create [OPTIONS] [arg...]

Create a machine

Description:
   Run 'docker-machine create --driver name --help' to include the create flags for that driver in the help text.

Options:

   --ca-cert <BASE64_CACERT>																			                Trust CA for the Harvester URL [$HARVESTER_CA_CERT]
   --cert <BASE64_CERT>	                                                                                                                                                                        Client Certificate to authenticate user with Harvester's KubeAPI Server [$HARVESTER_CERT]
   --cpus "1"																							Desired number of CPU cores of the VM [$HARVESTER_VM_CPUS]
   --disk-size "10Gi"																						Desired Size of Main Disk of the VM [$HARVESTER_VM_DISK_SIZE]
   --driver, -d "virtualbox"																					Driver to create machine with. [$MACHINE_DRIVER]
   --engine-env [--engine-env option --engine-env option]																	Specify environment variables to set in the engine
   --engine-insecure-registry [--engine-insecure-registry option --engine-insecure-registry option]												Specify insecure registries to allow with the created engine
   --engine-install-url "https://get.docker.com"																		Custom URL to use for engine installation [$MACHINE_DOCKER_INSTALL_URL]
   --engine-label [--engine-label option --engine-label option]																	Specify labels for the created engine
   --engine-opt [--engine-opt option --engine-opt option]																	Specify arbitrary flags to include with the created engine in the form flag=value
   --engine-registry-mirror [--engine-registry-mirror option --engine-registry-mirror option]													Specify registry mirrors to use [$ENGINE_REGISTRY_MIRROR]
   --engine-storage-driver 																					Specify a storage driver to use with the engine
   --harvester-url "https://192.168.0.1:6443"																			URL to Access Harvester's underlying Kubernetes API [$HARVESTER_URL]
   --image-id "image-fjh7c"																					Image ID on which VM will be based [$HARVESTER_VM_IMAGE_ID]
   --key <BASE64_KEY>									                                                                                                        Client Key to authenticate user with Harvester's KubeAPI Server [$HARVESTER_KEY]
   --keypair "macos"																						SSH KeyPair name (in Harvester's UI) to use to connect to VM [$HARVESTER_SSH_KEYNAME]
   --mem-size "2Gi"																						Desired Memory of the VM [$HARVESTER_VM_MEM_SIZE]
   --namespace "default"																					Kubernetes Namespace in which to create VM [$HARVESTER_VM_NAMESPACE]
   --ssh-key-path "~/.ssh/id_rsa"																			        Path of the SSH Private Key to be used to connect to VMs [$HARVESTER_SSH_KEY_PATH]
   --ssh-user "ubuntu"																						SSH user with Harvester's KubeAPI Server [$HARVESTER_SSH_USER]
   --swarm																							Configure Machine to join a Swarm cluster
   --swarm-addr 																						addr to advertise for Swarm (default: detect and use the machine IP)
   --swarm-discovery 																						Discovery service to use with Swarm
   --swarm-experimental																						Enable Swarm experimental features
   --swarm-host "tcp://0.0.0.0:3376"																				ip/socket to listen on for Swarm master
   --swarm-image "swarm:latest"																					Specify Docker image to use for Swarm [$MACHINE_SWARM_IMAGE]
   --swarm-join-opt [--swarm-join-opt option --swarm-join-opt option]																Define arbitrary flags for Swarm join
   --swarm-master																						Configure Machine to be a Swarm master
   --swarm-opt [--swarm-opt option --swarm-opt option]																		Define arbitrary flags for Swarm master
   --swarm-strategy "spread"																					Define a default scheduling strategy for Swarm
   --tls-san [--tls-san option --tls-san option]																		Support extra SANs for TLS certs, important if using the Pod Network
   --vm-description "Test VM in Harvester"																			Description of the Virtual Machine in Harvester [$HARVESTER_VIRTUAL_MACHINE_DESCRIPTION]
   --vm-name "ubuntu-test"																				        Desired Virtual Machine Name in Harvester [$HARVESTER_VIRTUAL_MACHINE_NAME]
```

## Parameters
The Harvester Driver for Docker Machine needs a number of parameters for creating a VM. These are summarized in the following table:
| Name      | Description | Environment variable | Optional|
|---      |---|---|---|
| vm-name     | Desired Virtual Machine Name in Harvester | HARVESTER_VIRTUAL_MACHINE_NAME ||
|namespace    | Kubernetes Namespace in which to create VM|HARVESTER_VM_NAMESPACE| X |
|vm-description    | Description of the Virtual Machine in Harvester|HARVESTER_VIRTUAL_MACHINE_DESCRIPTION| |
|ssh-user     | SSH user with Harvester's KubeAPI Server|HARVESTER_SSH_USER| |
|ssh-key-path     | Path of the SSH Private Key to be used to connect to VMs|HARVESTER_SSH_KEY_PATH| |
|keypair    | SSH KeyPair name to use to connect to VM|HARVESTER_SSH_KEYNAME| |
|image-id   | Image ID on which VM will be based|HARVESTER_VM_IMAGE_ID| |
|disk-size    | Desired Size of Main Disk of the VM|HARVESTER_VM_DISK_SIZE| |
|mem-size   | Desired Memory of the VM|HARVESTER_VM_MEM_SIZE| |
| cpus    | Desired number of CPU cores of the VM|HARVESTER_VM_CPUS| X |
|harvester-url    | URL to Access Harvester|HARVESTER_URL| |
|  ca-cert    | Base64 Encoded Trust CA for the Harvester URL|HARVESTER_CA_CERT| |
|  cert   | Base64 Encoded Client Certificate to authenticate user with Harvester's KubeAPI Server|HARVESTER_CERT| |
|  key    | Base64 Encoded Client Key to authenticate user with Harvester's KubeAPI Server|HARVESTER_KEY| |
