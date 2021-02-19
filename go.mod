module github.com/belgaied2/docker-machine-driver-harvester

go 1.12

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190221213512-86fb29eff628

require (
	github.com/docker/docker v20.10.3+incompatible // indirect
	github.com/docker/machine v0.16.2
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/rancher/machine v0.13.0
	github.com/spf13/pflag v1.0.3
	github.com/zach-klippenstein/goregen v0.0.0-20160303162051-795b5e3961ea
	k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.0.0-20190228174230-b40b2a5939e4
	kubevirt.io/client-go v0.19.0
	kubevirt.io/containerized-data-importer v1.8.1-0.20190516083534-83c12eaae2ed
)
