package harvester

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"

	restclient "k8s.io/client-go/rest"

	apiv1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	regen "github.com/zach-klippenstein/goregen"
	v1 "kubevirt.io/client-go/api/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/containerized-data-importer/pkg/apis/core/v1alpha1"
)

const (
	vmAnnotationDescription = "field.cattle.io/description"
	vmAnnotationNetworkIps  = "networks.harvester.cattle.io/ips"
	dvAnnotationImageID     = "harvester.cattle.io/imageId"
	dvSourceHTTPURLPrefix   = "http://minio.harvester-system:9000/vm-images/"
	defaultSSHUser          = "ubuntu"
	// defaultVmLabels	= {
	// 	"harvester.cattle.io/creator": "harvester"}
	defaultVMName        = "ubuntu-client-go-2"
	defaultVMDescription = "Test request for Kubevirt"
	defaultSSHKeyName    = "macos"
	defaultSSHKeyPath    = "~/.ssh/MacOSsKey.pem"
	defaultVMImageID     = "image-fjh7c"
	defaultDiskSize      = "10Gi"
	defaultMemSize       = "2Gi"
	defaultNbCPUCores    = 1
	defaultHarvesterHost = "https://192.168.0.109:6443"
	defaultCaCertBase64  = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUyTURneU5ESXhNREF3SGhjTk1qQXhNakUzTWpFMU5UQXdXaGNOTXpBeE1qRTFNakUxTlRBdwpXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUyTURneU5ESXhNREF3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFTUTFHTTJJVXlUUTlnaFU5RGw5Mkp5ckZrYW5FMmRPOEhURGNSa2RIQXoKRi9pc3Bzb2lrSTlsUkdEczNRZnlWZHBMK1Yybk1aclFXbTNnaHJRUnc0bTRvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXFMKzhXRWFnVGhxKzlWOUdkZEtiCnY1MEtXOE13Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU00NUNhcCt3USsxNW9FUlFORVZBVWZ0Q3RidVJTYTAKV0ljQ24vMi8wVVVkQWlBSGd3ZEdzYlk4YUdyWTBXL3RjN1FSREROOFE5S2tUNFp6RHR5KzNzMmphQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
	defaultCertBase64    = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrakNDQVRlZ0F3SUJBZ0lJZlUyTU9TVTZQVFF3Q2dZSUtvWkl6ajBFQXdJd0l6RWhNQjhHQTFVRUF3d1kKYXpOekxXTnNhV1Z1ZEMxallVQXhOakE0TWpReU1UQXdNQjRYRFRJd01USXhOekl4TlRVd01Gb1hEVEl4TVRJeApOekl4TlRVd01Gb3dNREVYTUJVR0ExVUVDaE1PYzNsemRHVnRPbTFoYzNSbGNuTXhGVEFUQmdOVkJBTVRESE41CmMzUmxiVHBoWkcxcGJqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJOd3NJNDdyMnpiZ3hLUG8KYXJmSkdmRHN6M3pRT2hSNmM4UlAxU2tjc2lObEwwYlliRll1T2NjejFpV1RNZHRXK1pkYzBhems0MDB5TlBNeAozWVZTcUhtalNEQkdNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBakFmCkJnTlZIU01FR0RBV2dCUmw5R2l3eXUzRjRlVHBhYjRsSTAzMUkxcC9lREFLQmdncWhrak9QUVFEQWdOSkFEQkcKQWlFQWxvT0J6amozak5uWFk2dFlCSEJYMGVwbmQrVXVzaWhLSlBrSjdFbndqMG9DSVFEOWt4VjNoQzBJczlCRQpUbzJEM2Rnb2lpVXp1ZmNoUG5wOEhzS04xN0NyL2c9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlCZGpDQ0FSMmdBd0lCQWdJQkFEQUtCZ2dxaGtqT1BRUURBakFqTVNFd0h3WURWUVFEREJock0zTXRZMnhwClpXNTBMV05oUURFMk1EZ3lOREl4TURBd0hoY05NakF4TWpFM01qRTFOVEF3V2hjTk16QXhNakUxTWpFMU5UQXcKV2pBak1TRXdId1lEVlFRRERCaHJNM010WTJ4cFpXNTBMV05oUURFMk1EZ3lOREl4TURBd1dUQVRCZ2NxaGtqTwpQUUlCQmdncWhrak9QUU1CQndOQ0FBVDJLUlNkMzFJWXhucHNsOWJQZ0ZJQ3NoMEFJcGRGOUg5V21hUVo1OFRPCmhqRFFkelZGbFhJK3c4UFl0MlFNVlVYYWEwYVV4eWtOWkU0Q0VoM29IL3FPbzBJd1FEQU9CZ05WSFE4QkFmOEUKQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVaZlJvc01ydHhlSGs2V20rSlNOTgo5U05hZjNnd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ0RBdzRaZDM0L1dTTFJIZ3VibmluRmROVlJlMXI1akd1CldjZEMzTUdLT1ZzQ0lISWhBcERXZGdRV0I0Q3gwQ0NWRWZ6c0U2emZuVWlPQWZjQ2crNXdzRmU2Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
	defaultKeyBase64     = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU9haC93MFY5UlQwZ3FqN1lYZy9oUlJjV1lxYWFBUEE1SUtpeDFBTzFJZGNvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFM0N3amp1dmJOdURFbytocXQ4a1o4T3pQZk5BNkZIcHp4RS9WS1J5eUkyVXZSdGhzVmk0NQp4elBXSlpNeDIxYjVsMXpSck9UalRUSTA4ekhkaFZLb2VRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	defaultNamespace     = "default"
)

const (
	// flVmLabels = map[string]string{
	// 	"harvester.cattle.io/creator": "harvester"}
	flVMName        = "vm-name"
	flVMDescription = "vm-description"
	flSSHUser       = "ssh-user"
	flSSHKeyName    = "keypair"
	flVMImageID     = "image-id"
	flDiskSize      = "disk-size"
	flMemSize       = "mem-size"
	flNbCPUCores    = "cpus"
	flHarvesterHost = "harvester-url"
	flCaCertBase64  = "ca-cert"
	flCertBase64    = "cert"
	flKeyBase64     = "key"
	flNamespace     = "namespace"
	flSSHKeyPath    = "ssh-key-path"
)

const (
	sshPort    = 22
	driverName = "harvester"
)

// Driver represents Harvester Docker Machine Driver.
type Driver struct {
	*drivers.BaseDriver

	VMLabels      map[string]string
	VMName        string
	VMDescription string
	SSHKeyName    string
	VMImageID     string
	DiskSize      string
	MemSize       string
	NBCPUCores    uint32
	HarvesterHost string
	CACertBase64  string
	CertBase64    string
	KeyBase64     string
	Namespace     string
	DockerPort    int
	VM            *v1.VirtualMachine
}

// NewDriver returns a new driver instance.
func NewDriver(hostName, storePath string) *Driver {
	// NOTE(ahmetalpbalkan): any driver initialization I do here gets lost
	// afterwards, especially for non-Create RPC calls. Therefore I am mostly
	// making rest of the driver stateless by just relying on the following
	// piece of info.
	d := &Driver{
		HarvesterHost: defaultHarvesterHost,
		CACertBase64:  defaultCaCertBase64,
		CertBase64:    defaultCertBase64,
		KeyBase64:     defaultKeyBase64,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return d
}

// GetCreateFlags returns list of create flags driver accepts.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   flVMName,
			Usage:  "Desired Virtual Machine Name in Harvester",
			EnvVar: "HARVESTER_VIRTUAL_MACHINE_NAME",
			Value:  defaultVMName,
		},
		mcnflag.StringFlag{
			Name:   flNamespace,
			Usage:  "Kubernetes Namespace in which to create VM",
			EnvVar: "HARVESTER_VM_NAMESPACE",
			Value:  defaultNamespace,
		},
		mcnflag.StringFlag{
			Name:   flVMDescription,
			Usage:  "Description of the Virtual Machine in Harvester",
			EnvVar: "HARVESTER_VIRTUAL_MACHINE_DESCRIPTION",
			Value:  defaultVMDescription,
		},
		mcnflag.StringFlag{
			Name:   flSSHUser,
			Usage:  "SSH user with Harvester's KubeAPI Server",
			EnvVar: "HARVESTER_SSH_USER",
			Value:  defaultSSHUser,
		},
		mcnflag.StringFlag{
			Name:   flSSHKeyName,
			Usage:  "SSH KeyPair name to use to connect to VM",
			EnvVar: "HARVESTER_SSH_KEYNAME",
			Value:  defaultSSHKeyName,
		},
		mcnflag.StringFlag{
			Name:   flVMImageID,
			Usage:  "Image ID on which VM will be based",
			EnvVar: "HARVESTER_VM_IMAGE_ID",
			Value:  defaultVMImageID,
		},
		mcnflag.StringFlag{
			Name:   flDiskSize,
			Usage:  "Desired Size of Main Disk of the VM",
			EnvVar: "HARVESTER_VM_DISK_SIZE",
			Value:  defaultDiskSize,
		},
		mcnflag.StringFlag{
			Name:   flMemSize,
			Usage:  "Desired Memory of the VM",
			EnvVar: "HARVESTER_VM_MEM_SIZE",
			Value:  defaultMemSize,
		},
		mcnflag.IntFlag{
			Name:   flNbCPUCores,
			Usage:  "Desired number of CPU cores of the VM",
			EnvVar: "HARVESTER_VM_CPUS",
			Value:  defaultNbCPUCores,
		},
		mcnflag.StringFlag{
			Name:   flHarvesterHost,
			Usage:  "URL to Access Harvester",
			EnvVar: "HARVESTER_URL",
			Value:  defaultHarvesterHost,
		},
		mcnflag.StringFlag{
			Name:   flCaCertBase64,
			Usage:  "Trust CA for the Harvester URL",
			EnvVar: "HARVESTER_CA_CERT",
			Value:  defaultCaCertBase64,
		},
		mcnflag.StringFlag{
			Name:   flCertBase64,
			Usage:  "Client Certificate to authenticate user with Harvester's KubeAPI Server",
			EnvVar: "HARVESTER_CERT",
			Value:  defaultCertBase64,
		},
		mcnflag.StringFlag{
			Name:   flKeyBase64,
			Usage:  "Client Key to authenticate user with Harvester's KubeAPI Server",
			EnvVar: "HARVESTER_KEY",
			Value:  defaultKeyBase64,
		},
		mcnflag.StringFlag{
			Name:   flSSHKeyPath,
			Usage:  "Path of the SSH Private Key to be used to connect to VMs",
			EnvVar: "HARVESTER_SSH_KEY_PATH",
			Value:  defaultSSHKeyPath,
		},
	}
}

// requiredOptionError forms an error from the error indicating the option has
// to be provided with a value for this driver.
type requiredOptionError string

func (r requiredOptionError) Error() string {
	return fmt.Sprintf("%s driver requires the %q option.", driverName, string(r))
}

// SetConfigFromFlags initializes driver values from the command line values
// and checks if the arguments have values.
func (d *Driver) SetConfigFromFlags(fl drivers.DriverOptions) error {

	// Required string flags
	flags := []struct {
		target *string
		flag   string
	}{
		{&d.BaseDriver.SSHUser, flSSHUser},
		{&d.VMName, flVMName},
		{&d.VMDescription, flVMDescription},
		{&d.SSHKeyName, flSSHKeyName},
		{&d.VMImageID, flVMImageID},
		{&d.DiskSize, flDiskSize},
		{&d.MemSize, flMemSize},
		{&d.HarvesterHost, flHarvesterHost},
		{&d.CACertBase64, flCaCertBase64},
		{&d.CertBase64, flCertBase64},
		{&d.KeyBase64, flKeyBase64},
		{&d.SSHKeyPath, flSSHKeyPath},
	}
	for _, f := range flags {
		*f.target = fl.String(f.flag)
		if *f.target == "" {
			return requiredOptionError(f.flag)
		}
	}

	// Optional flags or Flags of other types
	d.NBCPUCores = uint32(fl.Int(flNbCPUCores))
	d.Namespace = fl.String(flNamespace)

	// Set flags on the BaseDriver
	d.BaseDriver.SSHPort = sshPort
	d.VMLabels = map[string]string{
		"harvester.cattle.io/creator": "harvester",
	}
	d.SetSwarmConfigFromFlags(fl)

	log.Debug("Set configuration from flags.")
	return nil
}

// DriverName returns the name of the driver.
func (d *Driver) DriverName() string { return driverName }

func newTrue() *bool {
	b := true
	return &b
}

// PreCreateCheck validates if driver values are valid to create the machine.
func (d *Driver) PreCreateCheck() (err error) {

	// c, err := d.getHarvesterClient()

	// existingVM, err := c.VirtualMachine(d.namespace).Get(d.vmName, &k8smetav1.GetOptions{})
	// if err != nil {
	// 	return fmt.Errorf("Virtual Machine with name %s already exists", existingVM.Name)
	// }

	return nil
}

// GetHarvesterClient creates a Client for Harvester from Config input
func (d *Driver) getHarvesterClient() (kubecli.KubevirtClient, error) {
	// kubecli.DefaultClientConfig() prepares config using kubeconfig.
	// typically, you need to set env variable, KUBECONFIG=<path-to-kubeconfig>/.kubeconfig
	// clientConfig := kubecli.DefaultClientConfig(&pflag.FlagSet{})
	caCertBytes, errCA := base64.StdEncoding.DecodeString(d.CACertBase64)
	certBytes, errCert := base64.StdEncoding.DecodeString(d.CertBase64)
	keyBytes, errKey := base64.StdEncoding.DecodeString(d.KeyBase64)

	if errCA != nil || errCert != nil || errKey != nil {
		fmt.Println("An error happened during Base64 decoding of input certificate strings. The following error happened: %w", errCA)
	}
	clientConfig := restclient.Config{
		Host: d.HarvesterHost,
		TLSClientConfig: restclient.TLSClientConfig{
			ServerName: "harvester",
			CAData:     caCertBytes,
			CertData:   certBytes,
			KeyData:    keyBytes,
		},
	}

	// get the kubevirt client, using which kubevirt resources can be managed.
	return kubecli.GetKubevirtClientFromRESTConfig(&clientConfig)

}

// Create will create the VM and return error if it fails
func (d *Driver) Create() error {
	sc := "longhorn"
	dsAPIGroup := "storage.k8s.io"
	diskRandomID := randomID()
	pvcName := d.VMName + "-disk-0-" + diskRandomID
	vmiLabels := d.VMLabels
	vmiLabels["harvester.cattle.io/vmName"] = d.VMName

	// sshHost, _ := d.GetSSHHostname()
	// d.vmLabels["SSHHost"] = sshHost

	virtClient, err := d.getHarvesterClient()

	// var pvcDatasource apiv1.PersistentVolumeClaim
	ubuntuVM := &v1.VirtualMachine{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      d.VMName,
			Namespace: d.Namespace,
			Annotations: map[string]string{
				vmAnnotationDescription: d.VMDescription,
				vmAnnotationNetworkIps:  "[]",
			},
			Labels: d.VMLabels,
		},
		Spec: v1.VirtualMachineSpec{
			Running: newTrue(),
			DataVolumeTemplates: []v1alpha1.DataVolume{
				{
					ObjectMeta: k8smetav1.ObjectMeta{
						Name: pvcName,
						Annotations: map[string]string{
							dvAnnotationImageID: d.Namespace + "/" + d.VMImageID,
						},
					},
					Spec: v1alpha1.DataVolumeSpec{
						Source: v1alpha1.DataVolumeSource{
							HTTP: &v1alpha1.DataVolumeSourceHTTP{
								URL: dvSourceHTTPURLPrefix + d.VMImageID,
							},
						},
						PVC: &apiv1.PersistentVolumeClaimSpec{
							AccessModes: []apiv1.PersistentVolumeAccessMode{
								"ReadWriteOnce",
							},
							Resources: apiv1.ResourceRequirements{
								Requests: apiv1.ResourceList{
									"storage": resource.MustParse(d.DiskSize),
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
					Annotations: vmiAnnotations(pvcName, d.SSHKeyName),
					Labels:      vmiLabels,
				},
				Spec: v1.VirtualMachineInstanceSpec{
					Hostname: d.VMName,
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
							Cores:   d.NBCPUCores,
							Sockets: d.NBCPUCores,
							Threads: d.NBCPUCores,
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
								"memory": resource.MustParse(d.MemSize),
							},
						},
					},
				},
			},
		},
	}

	println("Creating Virtual Machine ...")
	d.VM, err = virtClient.VirtualMachine(d.Namespace).Create(ubuntuVM)

	if err != nil {
		fmt.Println("Error! : ", err)
	}

	sshSvc := &apiv1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      d.VMName,
			Namespace: d.Namespace,
			Labels:    d.VM.Labels,
		},
		Spec: apiv1.ServiceSpec{
			Ports: []apiv1.ServicePort{
				{
					Name: "ssh",
					Port: 22,
					TargetPort: intstr.IntOrString{
						IntVal: 22,
					},
				},
			},
			Selector: d.VMLabels,
			Type:     apiv1.ServiceTypeNodePort,
		},
	}

	createdSvc, err := virtClient.Core().Services(d.Namespace).Create(sshSvc)
	// nodePort := createdSvc.Spec.Ports[0].NodePort
	if len(createdSvc.Spec.Ports) != 0 {
		d.SSHPort = int(createdSvc.Spec.Ports[0].NodePort)
	}

	dockerSvcName := fmt.Sprint(d.VMName, "-docker")
	dockerSvc := &apiv1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      dockerSvcName,
			Namespace: d.Namespace,
			Labels:    d.VM.Labels,
		},
		Spec: apiv1.ServiceSpec{
			Ports: []apiv1.ServicePort{
				{
					Name: "docker",
					Port: 32376,
					TargetPort: intstr.IntOrString{
						IntVal: 32376,
					},
					NodePort: 32376,
				},
			},
			Selector: d.VMLabels,
			Type:     apiv1.ServiceTypeNodePort,
		},
	}

	dockerCreatedSvc, err := virtClient.Core().Services(d.Namespace).Create(dockerSvc)
	// nodePort := createdSvc.Spec.Ports[0].NodePort
	if len(dockerCreatedSvc.Spec.Ports) != 0 {
		d.DockerPort = int(dockerCreatedSvc.Spec.Ports[0].NodePort)
	}

	if err != nil {
		println(err.Error())
	} else {
		println("Virtual Machine Created Successfully")
	}

	return err

}

// Remove a VM from Harvester
func (d *Driver) Remove() error {
	c, err := d.getHarvesterClient()

	if err != nil {
		return err
	}

	return c.VirtualMachine(d.Namespace).Delete(d.VMName, &k8smetav1.DeleteOptions{})
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
		fmt.Println("Random function was not successful!")
		return ""
	}
	return res
}

//GetIP returns public IP address or hostname of the machine instance.
func (d *Driver) GetIP() (string, error) {

	c, err := d.getHarvesterClient()
	if err != nil {
		return "", err
	}

	vmi, err := c.VirtualMachineInstance(d.Namespace).Get(d.VMName, &k8smetav1.GetOptions{})
	if err != nil {
		return "", err
	}

	return vmi.Status.Interfaces[0].IP, err
}

// GetSSHHostname returns an IP address or hostname for the machine instance.
func (d *Driver) GetSSHHostname() (string, error) {

	podNetwork := d.VM.Spec.Template.Spec.Networks[0].Pod
	if podNetwork != nil {
		return d.GetHostIP()
	}
	return d.GetIP()

}

// GetHostIP gets the IP of the Host on which the machine is running
func (d *Driver) GetHostIP() (string, error) {

	c, err := d.getHarvesterClient()
	podSelector := fmt.Sprint("harvester.cattle.io/vmName=", d.VMLabels["harvester.cattle.io/vmName"])
	println("PodSelector to use: " + podSelector)
	podList, err := c.Core().Pods(d.Namespace).List(k8smetav1.ListOptions{
		LabelSelector: podSelector,
	})

	if err != nil || len(podList.Items) == 0 {
		return "", fmt.Errorf("No VM is scheduled on the cluster")
	}
	return podList.Items[0].Status.HostIP, nil
}

// GetSSHUsername returns an IP address or hostname for the machine instance.
func (d *Driver) GetSSHUsername() string {
	if d.SSHUser != "" {
		return d.SSHUser
	}
	return ""
}

// GetSSHPort returns an IP address or hostname for the machine instance.
func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort != 0 {
		return d.SSHPort, nil
	}
	return 0, fmt.Errorf("No SSH Port defined")
}

// GetSSHKeyPath return the SSH Key Path
func (d *Driver) GetSSHKeyPath() string {

	if d.SSHKeyPath != "" {
		return d.SSHKeyPath
	}
	return ""
}

// ErrHostIsNotRunning is an error that shows that the VM is not Running
var ErrHostIsNotRunning = errors.New("Host is not running")

// MustBeRunning will return an error if the machine is not in a running state.
func MustBeRunning(d *Driver) error {
	s, err := d.GetState()
	if err != nil {
		return err
	}

	if s != state.Running {
		return ErrHostIsNotRunning
	}

	return nil
}

// GetURL returns a socket address to connect to Docker engine of the machine
// instance.
func (d *Driver) GetURL() (string, error) {

	if err := MustBeRunning(d); err != nil {
		return "", err
	}

	// NOTE (ahmetalpbalkan) I noticed that this is not used until machine is
	// actually created and provisioned. By then GetIP() should be returning
	// a non-empty IP address as the VM is already allocated and connected to.
	ip, err := d.GetHostIP()
	if err != nil {
		return "", err
	}
	u := (&url.URL{
		Scheme: "tcp",
		Host:   net.JoinHostPort(ip, fmt.Sprintf("%d", d.DockerPort)),
	}).String()
	log.Debugf("Machine URL is resolved to: %s", u)
	return u, nil
}

// GetState returns the state of the virtual machine role instance.
func (d *Driver) GetState() (state.State, error) {

	c, err := d.getHarvesterClient()
	if err != nil {
		return state.None, err
	}
	vmi, err := c.VirtualMachineInstance(d.Namespace).Get(d.VMName, &k8smetav1.GetOptions{})
	if err != nil {
		return state.None, err
	}

	vmiPhase := vmi.Status.Phase

	machineState := machineStateForVMIPhase(vmiPhase)
	log.Debugf("Determined Azure PowerState=%q, docker-machine state=%q",
		vmiPhase, machineState)
	return machineState, nil
}

func machineStateForVMIPhase(vmiPhase v1.VirtualMachineInstancePhase) state.State {
	switch state := vmiPhase; state {
	case "Pending":
		return 6
	case "Scheduling":
		return 6
	case "Scheduled":
		return 6
	case "Running":
		return 1
	case "Succeeded":
		return 4
	case "Failed":
		return 7
	case "Unknown":
		return 0
	default:
		return 0
	}
}

// Start issues a power on for the virtual machine instance.
func (d *Driver) Start() error {

	c, err := d.getHarvesterClient()
	if err != nil {
		return err
	}

	vm, err := c.VirtualMachine(d.Namespace).Get(d.VMName, &k8smetav1.GetOptions{})
	*vm.Spec.Running = true

	_, err = c.VirtualMachine(d.Namespace).Update(vm)
	return err
}

// Stop issues a power off for the virtual machine instance.
func (d *Driver) Stop() error {

	c, err := d.getHarvesterClient()
	if err != nil {
		return err
	}

	vm, err := c.VirtualMachine(d.Namespace).Get(d.VMName, &k8smetav1.GetOptions{})
	*vm.Spec.Running = false

	_, err = c.VirtualMachine(d.Namespace).Update(vm)
	return err
}

// Restart reboots the virtual machine instance.
func (d *Driver) Restart() error {

	err := d.Stop()
	if err != nil {
		return err
	}
	return d.Start()
}

// Kill stops the virtual machine role instance.
func (d *Driver) Kill() error {

	c, err := d.getHarvesterClient()
	if err != nil {
		return err
	}

	vm, err := c.VirtualMachine(d.Namespace).Get(d.VMName, &k8smetav1.GetOptions{})
	*vm.Spec.Running = false
	*vm.Spec.Template.Spec.TerminationGracePeriodSeconds = 0

	_, err = c.VirtualMachine(d.Namespace).Update(vm)
	return err
}

// func main() {

// 	d := NewDriver("", "")
// 	d.caCertBase64 = defaultCaCertBase64
// 	d.certBase64 = defaultCertBase64
// 	d.diskSize = defaultDiskSize
// 	d.harvesterHost = defaultHarvesterHost
// 	d.keyBase64 = defaultKeyBase64
// 	d.memSize = defaultMemSize
// 	d.namespace = defaultNamespace
// 	d.nbCPUCores = defaultNbCPUCores
// 	d.sshKeyName = defaultSSHKeyName
// 	d.vmDescription = defaultVMDescription
// 	d.vmImageID = defaultVMImageID
// 	d.vmName = defaultVMName
// 	d.vmLabels = map[string]string{
// 		"harvester.cattle.io/creator": "harvester",
// 	}
// 	d.vmLabels["harvester.cattle.io/vmName"] = d.vmName

// 	// d.Create()
// 	c, _ := d.getHarvesterClient()
// 	d.vm, _ = c.VirtualMachine(d.namespace).Get(d.vmName, &k8smetav1.GetOptions{})
// 	svc, _ := c.Core().Services(d.namespace).Get(d.vmName, k8smetav1.GetOptions{})
// 	sshPort := svc.Spec.Ports[0].NodePort
// 	vmState, _ := d.GetState()
// 	for vmState != state.Running {
// 		println("VM is not yet running, waiting another 10 seconds...")
// 		time.Sleep(10 * time.Second)
// 		vmState, _ = d.GetState()
// 	}
// 	println("VM Created, Getting SSH information")
// 	sshHost, _ := d.GetSSHHostname()

// 	// sshPort, _ := d.GetSSHPort()
// 	fmt.Printf("SSH PORT: %d\nSSH HOST: %s\nSSH User: %s\nSSH Keypath: %s\n", sshPort, sshHost, d.GetSSHUsername(), d.GetSSHKeyPath())
// 	println("PodNetworkCIDR for VM: ", *&d.vm.Spec.Template.Spec.Networks[0].Pod)
// }
