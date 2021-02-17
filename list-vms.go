package main

import (
	"log"

	apiv1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	regen "github.com/zach-klippenstein/goregen"
	v1 "kubevirt.io/client-go/api/v1"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/containerized-data-importer/pkg/apis/core/v1alpha1"
)

const (
	vmAnnotationDescription = "field.cattle.io/description"
	vmAnnotationNetworkIps  = "networks.harvester.cattle.io/ips"
	dvAnnotationImageID     = "harvester.cattle.io/imageId"
	dvSourceHTTPURLPrefix   = "http://minio.harvester-system:9000/vm-images/"
)

var (
	vmLabels = map[string]string{
		"harvester.cattle.io/creator": "harvester"}
	vmName        string = "ubuntu-client-go-2"
	vmDescription string = "Test request for Kubevirt"
	sshKeyName    string = "macos"
	vmImageID     string = "image-7knsw"
	diskSize      string = "10Gi"
	memSize       string = "2Gi"
	nbCPUCores    uint32 = 1
	harvesterHost string = ""
)

func main() {

	// kubecli.DefaultClientConfig() prepares config using kubeconfig.
	// typically, you need to set env variable, KUBECONFIG=<path-to-kubeconfig>/.kubeconfig
	// clientConfig := kubecli.DefaultClientConfig(&pflag.FlagSet{})
	clientConfig := clientcmd.ClientConfig{
		apiv1.HostAlias: {
			apiv1.Namespace: 
		}
	}
	clientConfig.Host = harvesterHost

	// retrive default namespace.
	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		log.Fatalf("error in namespace : %v\n", err)
	}

	// get the kubevirt client, using which kubevirt resources can be managed.
	virtClient, err := kubecli.GetKubevirtClientFromClientConfig(clientConfig)

	_ = createVM(virtClient, namespace, vmName, vmDescription, sshKeyName, vmImageID, diskSize, memSize, nbCPUCores)

}

func newTrue() *bool {
	b := true
	return &b
}

func createVM(
	virtClient kubecli.KubevirtClient,
	namespace string,
	vmName string,
	vmDescription string,
	sshKeyName string,
	vmImageID string,
	diskSize string,
	memSize string,
	nbCPUCores uint32,
) v1.VirtualMachine {
	sc := "longhorn"
	dsAPIGroup := "storage.k8s.io"
	diskRandomID := randomID()
	pvcName := vmName + "-disk-0-" + diskRandomID
	vmiLabels := vmLabels
	vmiLabels["harvester.cattle.io/vmName"] = vmName

	// var pvcDatasource apiv1.PersistentVolumeClaim
	ubuntuVM := &v1.VirtualMachine{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      vmName,
			Namespace: namespace,
			Annotations: map[string]string{
				vmAnnotationDescription: vmDescription,
				vmAnnotationNetworkIps:  "[]",
			},
			Labels: vmLabels,
		},
		Spec: v1.VirtualMachineSpec{
			Running: newTrue(),
			DataVolumeTemplates: []v1alpha1.DataVolume{
				{
					ObjectMeta: k8smetav1.ObjectMeta{
						Name: pvcName,
						Annotations: map[string]string{
							dvAnnotationImageID: namespace + "/" + vmImageID,
						},
					},
					Spec: v1alpha1.DataVolumeSpec{
						Source: v1alpha1.DataVolumeSource{
							HTTP: &v1alpha1.DataVolumeSourceHTTP{
								URL: dvSourceHTTPURLPrefix + vmImageID,
							},
						},
						PVC: &apiv1.PersistentVolumeClaimSpec{
							AccessModes: []apiv1.PersistentVolumeAccessMode{
								"ReadWriteOnce",
							},
							Resources: apiv1.ResourceRequirements{
								Requests: apiv1.ResourceList{
									"storage": resource.MustParse(diskSize),
								},
							},

							StorageClassName: &sc,
							DataSource: &apiv1.TypedLocalObjectReference{
								APIGroup: &dsAPIGroup,
							},
							// DataSource: nil,
						},
					},
				},
			},
			Template: &v1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{
					Annotations: vmiAnnotations(pvcName, sshKeyName),
					Labels:      vmiLabels,
				},
				Spec: v1.VirtualMachineInstanceSpec{
					Hostname: vmName,
					Networks: []v1.Network{
						{
							Name: "default",
							NetworkSource: v1.NetworkSource{
								Pod: v1.DefaultPodNetwork().Pod,
							},
						},
					},
					Volumes: []v1.Volume{
						{
							Name: "disk-0",
							VolumeSource: v1.VolumeSource{
								PersistentVolumeClaim: &apiv1.PersistentVolumeClaimVolumeSource{
									ClaimName: pvcName,
								},
							},
						},
						{
							Name: "cloudinitdisk",
							VolumeSource: v1.VolumeSource{
								CloudInitNoCloud: &v1.CloudInitNoCloudSource{
									UserData: "#cloud-config\nssh_authorized_keys:\n  - >\n    ssh-rsa\n    AAAAB3NzaC1yc2EAAAADAQABAAABAQCrO13CUFxoQ+DJQ6tDqKorbKqC0QGQWSmPEsYjLUKF0mbpk1LLiiEDhM1enEXJ7RXf0De5n6hnYeVgo1h2XiUmhfOOYhF23/GhLaFmMsu5heLH969IZpqh/17t/r//pONxt2mnkcCMmywptZ0PLXPjYfOIE8y87Q5gFw5APFmwvEUn0LxCK1odlDXWhedwLOtYjfFLNAowMaXDKvqZsPYow3EizDN64kIGwpIkBscqdZqi+vCBfFsr4tJg0jT2iVYu8tbf7sIK9y0on6/fQ1t9pAPCJbbSMBObns26ZLP2Ym0tXmgbCMHDEnWkjLUYr5XqOpc7f3SkYGb/JkNV5FmN\n    mohamed@mac.belgaied.name\n",
								},
							},
						},
					},
					Domain: v1.DomainSpec{
						CPU: &v1.CPU{
							Cores:   nbCPUCores,
							Sockets: nbCPUCores,
							Threads: nbCPUCores,
						},
						Devices: v1.Devices{
							Inputs: []v1.Input{
								{
									Bus:  "usb",
									Type: "tablet",
									Name: "tablet",
								},
							},
							Interfaces: []v1.Interface{
								{
									Name:  "default",
									Model: "virtio",
									InterfaceBindingMethod: v1.InterfaceBindingMethod{
										Masquerade: &v1.InterfaceMasquerade{},
									},
								},
							},
							Disks: []v1.Disk{
								{
									Name: "disk-0",
									DiskDevice: v1.DiskDevice{
										Disk: &v1.DiskTarget{
											Bus: "virtio",
										},
									},
								},
								{
									Name: "cloudinitdisk",
									DiskDevice: v1.DiskDevice{
										Disk: &v1.DiskTarget{
											Bus: "virtio",
										},
									},
								},
							},
						},
						Resources: v1.ResourceRequirements{
							Requests: apiv1.ResourceList{
								"memory": resource.MustParse(memSize),
							},
						},
					},
				},
			},
		},
	}

	println("Creating Virtual Machine ...")
	vm, err := virtClient.VirtualMachine(namespace).Create(ubuntuVM)

	if err != nil {
		println(err.Error())
	} else {
		println("Virtual Machine Created Successfully")
	}

	return *vm

}

func vmiAnnotations(pvcName string, sshKeyName string) map[string]string {
	return map[string]string{
		"harvester.cattle.io/diskNames": "[\"" + pvcName + "\"]",
		"harvester.cattle.io/sshNames":  "[\"" + sshKeyName + "\"]",
	}
}

func randomID() string {
	res, err := regen.Generate("[a-z]{3}[0-9][a-z]")
	if err != nil {
		return ""
	}
	return res

}
