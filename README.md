# Harvester Driver for Docker Machine

This repository is a Harvester Driver for Docker Machine. It uses the Kubernetes API underlying Harvester (since Harvester does not yet an official API) in order manage VM lifecycle.

The Create() operation will create an Object VirtualMachine with some labels for Harvester.

At the moment, integration with Docker is not perfect. When `docker-machine create -d harvester` is run, the docker-machine CLI will show errors, but the machine is correctly created, and setting the DOCKER_HOST, DOCKER_CERT environments variables manually get a working remote docker machine.

## Warning
This repo is not yet well documented and not fully functional, it is designed to be a POC for the Node Driver feature for Harvester in Rancher.
