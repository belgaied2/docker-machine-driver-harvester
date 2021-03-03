# Harvester Driver for Docker Machine

This repository is a Harvester Driver for Docker Machine. It uses the Kubernetes API underlying Harvester (since Harvester does not yet an official API) in order manage VM lifecycle.

The Create() operation will create an Object VirtualMachine with some labels for Harvester.

At the moment, integration with Docker is not perfect. Using `docker-machine create -d harvester` is run, a VM is successfully created in Harvester, and it is visible using `docker-machine ls`. However, some lifecycle steps are still buggy.

Also, since my knowledge in Harvester and the bridge network is lacking, I implemented NodePort services to connect to the VM from docker-machine.

## Warning
This repo is not yet well documented and not fully functional, it is designed to be a POC for the Node Driver feature for Harvester in Rancher.
