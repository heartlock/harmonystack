/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"code.google.com/p/gcfg"
	"github.com/docker/distribution/uuid"
	"github.com/golang/glog"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/portsbinding"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/heartlock/harmonystack/pkg/plugins"
	provider "github.com/heartlock/harmonystack/pkg/types"

	// import plugins
	_ "github.com/heartlock/harmonystack/pkg/plugins/openvswitch"
)

const (
	podNamePrefix     = "kube"
	securitygroupName = "kube-securitygroup-default"
	hostnameMaxLen    = 63

	// Service affinities
	ServiceAffinityNone     = "None"
	ServiceAffinityClientIP = "ClientIP"
)

var (
	adminStateUp = true

	ErrNotFound        = errors.New("NotFound")
	ErrMultipleResults = errors.New("MultipleResults")
)

// encoding.TextUnmarshaler interface for time.Duration
type MyDuration struct {
	time.Duration
}

func (d *MyDuration) UnmarshalText(text []byte) error {
	res, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = res
	return nil
}

type LoadBalancerOpts struct {
	LBMethod          string     `gcfg:"lb-method"`
	CreateMonitor     bool       `gcfg:"create-monitor"`
	MonitorDelay      MyDuration `gcfg:"monitor-delay"`
	MonitorTimeout    MyDuration `gcfg:"monitor-timeout"`
	MonitorMaxRetries uint       `gcfg:"monitor-max-retries"`
}

type PluginOpts struct {
	PluginName        string `gcfg:"plugin-name"`
	IntegrationBridge string `gcfg:"integration-bridge"`
}

// OpenDaylight is an implementation of network provider Interface for OpenDaylight.
type OpenDaylight struct {
	odlClient *OpenDaylightClient
	//TODO: 	verify identidy of tenant and authorize to operate source
	//TODO: lbOpts     LoadBalancerOpts
	pluginOpts PluginOpts
	ExtNetID   string
	Plugin     plugins.PluginInterface
}

type Config struct {
	Global struct {
		Url string `gcfg:"auth-url"`
		//TODO info for authorization
		ExtNetID string
	}
	LoadBalancer LoadBalancerOpts
	Plugin       PluginOpts
}

//TODO: func (cfg Config) toAuthOptions() AuthOptions

func NewOpenDaylight(config io.Reader) (*OpenDaylight, error) {
	var cfg Config
	err := gcfg.ReadInto(&cfg, config)
	if err != nil {
		glog.Warning("Failed to parse opendaylight configure file: %v", err)
		return nil, err
	}

	odl, err := NewOpenDaylightClient(&cfg)
	if err != nil {
		glog.Warning("Failed to create opendaylight client: %v", err)
		return nil, err
	}

	os := OpenDaylight{
		odlClient:  odl,
		pluginOpts: cfg.Plugin,
		ExtNetID:   cfg.Global.ExtNetID,
	}

	// init plugin
	if cfg.Plugin.PluginName != "" {
		integrationBriage := "br-int"
		if cfg.Plugin.IntegrationBridge != "" {
			integrationBriage = cfg.Plugin.IntegrationBridge
		}

		plugin, _ := plugins.GetNetworkPlugin(cfg.Plugin.PluginName)
		if plugin != nil {
			plugin.Init(integrationBriage)
			os.Plugin = plugin
		}
	}

	return &os, nil
}

func getHostName() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}

	return host
}

// Get opendaylight network by id
func (os *OpenDaylight) getOpenDaylightNetworkByID(id string) (*networks.Network, error) {
	opts := networks.ListOpts{ID: id}
	return os.getOpenDaylightNetwork(&opts)
}

// Get opendaylight network by name
func (os *OpenDaylight) getOpenDaylightNetworkByName(name string) (*networks.Network, error) {
	opts := networks.ListOpts{Name: name}
	return os.getOpenDaylightNetwork(&opts)
}

// Get opendaylight network
func (os *OpenDaylight) getOpenDaylightNetwork(opts *networks.ListOpts) (*networks.Network, error) {
	var osNetwork *networks.Network
	networkList, err := os.odlClient.ListNetwork(opts)
	if err != nil {
		return nil, err
	}
	if len(networkList) > 1 {
		return nil, ErrMultipleResults
	}

	if len(networkList) == 1 {
		osNetwork = &networkList[0]
	}

	if networkList == nil {
		return nil, ErrNotFound
	}

	return osNetwork, nil
}

// Get provider subnet by id
func (os *OpenDaylight) getProviderSubnet(osSubnetID string) (*provider.Subnet, error) {
	s, err := os.odlClient.GetSubnet(osSubnetID).Extract()
	if err != nil {
		glog.Errorf("Get opendaylight subnet failed: %v", err)
		return nil, err
	}

	var routes []*provider.Route
	for _, r := range s.HostRoutes {
		route := provider.Route{
			Nexthop:         r.NextHop,
			DestinationCIDR: r.DestinationCIDR,
		}
		routes = append(routes, &route)
	}

	providerSubnet := provider.Subnet{
		Uid:        s.ID,
		Cidr:       s.CIDR,
		Gateway:    s.GatewayIP,
		Name:       s.Name,
		Dnsservers: s.DNSNameservers,
		Routes:     routes,
	}

	return &providerSubnet, nil
}

// Get network by networkID
func (os *OpenDaylight) GetNetworkByID(networkID string) (*provider.Network, error) {
	osNetwork, err := os.getOpenDaylightNetworkByID(networkID)
	if err != nil {
		glog.Errorf("Get opendaylight network failed: %v", err)
		return nil, err
	}

	return os.OSNetworktoProviderNetwork(osNetwork)
}

// Get network by networkName
func (os *OpenDaylight) GetNetwork(networkName string) (*provider.Network, error) {
	osNetwork, err := os.getOpenDaylightNetworkByName(networkName)
	if err != nil {
		glog.Errorf("Get opendaylight network failed: %v", err)
		return nil, err
	}

	return os.OSNetworktoProviderNetwork(osNetwork)
}

func (os *OpenDaylight) OSNetworktoProviderNetwork(osNetwork *networks.Network) (*provider.Network, error) {
	var providerNetwork provider.Network
	var providerSubnets []*provider.Subnet
	providerNetwork.Name = osNetwork.Name
	providerNetwork.Uid = osNetwork.ID
	providerNetwork.Status = os.ToProviderStatus(osNetwork.Status)
	providerNetwork.TenantID = osNetwork.TenantID

	for _, subnetID := range osNetwork.Subnets {
		s, err := os.getProviderSubnet(subnetID)
		if err != nil {
			return nil, err
		}
		providerSubnets = append(providerSubnets, s)
	}

	providerNetwork.Subnets = providerSubnets

	return &providerNetwork, nil
}

func (os *OpenDaylight) ToProviderStatus(status string) string {
	switch status {
	case "ACTIVE":
		return "Active"
	case "BUILD":
		return "Pending"
	case "DOWN", "ERROR":
		return "Failed"
	default:
		return "Failed"
	}

	return "Failed"
}

// Create network
func (os *OpenDaylight) CreateNetwork(network *provider.Network) error {
	if len(network.Subnets) == 0 {
		return errors.New("Subnets is null")
	}

	// create network
	opts := networks.CreateOpts{
		Name:         network.Name,
		AdminStateUp: &adminStateUp,
		TenantID:     network.TenantID,
	}
	osNet, err := os.odlClient.CreateNetwork(opts).Extract()
	if err != nil {
		glog.Errorf("Create opendaylight network %s failed: %v", network.Name, err)
		return err
	}

	// create router
	routerOpts := routers.CreateOpts{
		Name:        network.Name,
		TenantID:    network.TenantID,
		GatewayInfo: &routers.GatewayInfo{NetworkID: os.ExtNetID},
	}
	osRouter, err := os.odlClient.CreateRouter(routerOpts).Extract()
	if err != nil {
		glog.Errorf("Create opendaylight router %s failed: %v", network.Name, err)
		delErr := os.DeleteNetwork(network.Name)
		if delErr != nil {
			glog.Errorf("Delete opendaylight network %s failed: %v", network.Name, delErr)
		}
		return err
	}

	// create subnets and connect them to router
	networkID := osNet.ID
	network.Status = os.ToProviderStatus(osNet.Status)
	network.Uid = osNet.ID
	for _, sub := range network.Subnets {
		// create subnet
		subnetOpts := subnets.CreateOpts{
			NetworkID:      networkID,
			CIDR:           sub.Cidr,
			Name:           sub.Name,
			IPVersion:      gophercloud.IPv4,
			TenantID:       network.TenantID,
			GatewayIP:      &sub.Gateway,
			DNSNameservers: sub.Dnsservers,
		}
		s, err := os.odlClient.CreateSubnet(subnetOpts).Extract()
		if err != nil {
			glog.Errorf("Create opendaylight subnet %s failed: %v", sub.Name, err)
			delErr := os.DeleteNetwork(network.Name)
			if delErr != nil {
				glog.Errorf("Delete opendaylight network %s failed: %v", network.Name, delErr)
			}
			return err
		}

		// add subnet to router
		opts := routers.AddInterfaceOpts{
			SubnetID: s.ID,
		}
		_, err = os.odlClient.AddInterface(osRouter.ID, opts).Extract()
		if err != nil {
			glog.Errorf("Create opendaylight subnet %s failed: %v", sub.Name, err)
			delErr := os.DeleteNetwork(network.Name)
			if delErr != nil {
				glog.Errorf("Delete opendaylight network %s failed: %v", network.Name, delErr)
			}
			return err
		}
	}

	return nil
}

// Update network
func (os *OpenDaylight) UpdateNetwork(network *provider.Network) error {
	// TODO: update network subnets
	return nil
}

func (os *OpenDaylight) getRouterByName(name string) (*routers.Router, error) {
	var result *routers.Router

	opts := routers.ListOpts{Name: name}
	routerList, err := os.odlClient.ListRouter(opts)
	if err != nil {
		return nil, err
	}
	if len(routerList) > 1 {
		return nil, ErrMultipleResults
	} else if len(routerList) == 1 {
		result = &routerList[0]
	} else if routerList == nil {
		return nil, ErrNotFound
	}
	return result, nil
}

// Delete network by networkName
func (os *OpenDaylight) DeleteNetwork(networkName string) error {
	osNetwork, err := os.getOpenDaylightNetworkByName(networkName)
	if err != nil {
		glog.Errorf("Get opendaylight network failed: %v", err)
		return err
	}

	if osNetwork != nil {
		// Delete ports
		opts := ports.ListOpts{NetworkID: osNetwork.ID}
		portList, err := os.odlClient.ListPort(opts)
		if err != nil {
			return err
		}

		for _, port := range portList {
			if port.DeviceOwner == "network:router_interface" {
				continue
			}

			err = os.odlClient.DeletePort(port.ID).ExtractErr()
			if err != nil {
				glog.Warningf("Delete port %v failed: %v", port.ID, err)
			}
		}

		if err != nil {
			glog.Errorf("Delete ports error: %v", err)
		}

		router, err := os.getRouterByName(networkName)
		if err != nil {
			glog.Errorf("Get opendaylight router %s error: %v", networkName, err)
			return err
		}

		// delete all subnets
		for _, subnet := range osNetwork.Subnets {
			if router != nil {
				opts := routers.RemoveInterfaceOpts{SubnetID: subnet}
				_, err := os.odlClient.RemoveInterface(router.ID, opts).Extract()
				if err != nil {
					glog.Errorf("Get opendaylight router %s error: %v", networkName, err)
					return err
				}
			}

			err = os.odlClient.DeleteSubnet(subnet).ExtractErr()
			if err != nil {
				glog.Errorf("Delete opendaylight subnet %s error: %v", subnet, err)
				return err
			}
		}

		// delete router
		if router != nil {
			err = os.odlClient.DeleteRouter(router.ID).ExtractErr()
			if err != nil {
				glog.Errorf("Delete opendaylight router %s error: %v", router.ID, err)
				return err
			}
		}

		// delete network
		err = os.odlClient.DeleteNetwork(osNetwork.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Delete opendaylight network %s error: %v", osNetwork.ID, err)
			return err
		}
	}

	return nil
}

// List all ports in the network
func (os *OpenDaylight) ListPorts(networkID, deviceOwner string) ([]ports.Port, error) {
	var results []ports.Port
	opts := ports.ListOpts{
		NetworkID:   networkID,
		DeviceOwner: deviceOwner,
	}
	portList, err := os.odlClient.ListPort(opts)

	if err != nil {
		glog.Errorf("Get opendaylight ports error: %v", err)
		return nil, err
	}

	for _, port := range portList {
		results = append(results, port)
	}
	return results, nil
}

//TODO: securityGroup

// Create an port
func (os *OpenDaylight) CreatePort(networkID, tenantID, portName, podHostname string) (*portsbinding.Port, error) {
	opts := portsbinding.CreateOpts{
		HostID:  getHostName(),
		DNSName: podHostname,
		CreateOptsBuilder: ports.CreateOpts{
			NetworkID:    networkID,
			Name:         portName,
			AdminStateUp: &adminStateUp,
			TenantID:     tenantID,
			DeviceID:     uuid.Generate().String(),
			DeviceOwner:  fmt.Sprintf("compute:%s", getHostName()),
		},
	}

	port, err := os.odlClient.CreatePort(opts).Extract()
	if err != nil {
		glog.Errorf("Create port %s failed: %v", portName, err)
		return nil, err
	}

	// Update dns_name in order to make sure it is correct
	updateOpts := portsbinding.UpdateOpts{
		DNSName: podHostname,
	}
	_, err = os.odlClient.UpdatePort(port.ID, updateOpts).Extract()
	if err != nil {
		os.odlClient.DeletePort(port.ID)
		glog.Errorf("Update port %s failed: %v", portName, err)
		return nil, err
	}

	return port, nil
}

// TODO: Bind an port to external network, return error

// TODO: Bind an port to external network, return floatingip binded

// TODO: Unbind an port from external

func (os *OpenDaylight) GetPort(name string) (*ports.Port, error) {
	opts := ports.ListOpts{Name: name}
	portList, err := os.odlClient.ListPort(opts)
	if err != nil {
		glog.Errorf("Get opendaylight ports error: %v", err)
		return nil, err
	}
	var port *ports.Port

	if len(portList) > 1 {
		return nil, ErrMultipleResults
	}

	if len(portList) == 0 {
		return nil, ErrNotFound
	}

	port = &portList[0]

	return port, err
}

// Delete port by portName
func (os *OpenDaylight) DeletePort(portName string) error {
	port, err := os.GetPort(portName)
	if err == ErrNotFound {
		glog.V(4).Infof("Port %s already deleted", portName)
		return nil
	} else if err != nil {
		glog.Errorf("Get opendaylight port %s failed: %v", portName, err)
		return err
	}

	if port != nil {
		err := os.odlClient.DeletePort(port.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Delete opendaylight port %s failed: %v", portName, err)
			return err
		}
	}

	return nil
}

func isNotFound(err error) bool {
	_, ok := err.(*gophercloud.ErrDefault404)
	return ok
}

// TODO: Get OpenDaylight LBAAS pool by name

// TODO: Get OpenDaylight LBAAS vip by ID

// TODO: Get OpenDaylight LBAAS vip by name

// TODO: Get OpenDaylight LBAAS vip by opts

// TODO: Get load balancer by name

// TODO: Create load balancer

// TODO: Update load balancer

// TODO: Delete load balancer

func (os *OpenDaylight) BuildPortName(podName, namespace, networkID string) string {
	return podNamePrefix + "_" + podName + "_" + namespace + "_" + networkID
}

// Setup pod
func (os *OpenDaylight) SetupPod(podName, namespace, podInfraContainerID string, network *provider.Network, containerRuntime string) error {
	portName := os.BuildPortName(podName, namespace, network.Uid)

	// get dns server ips
	dnsServers := make([]string, 0, 1)
	networkPorts, err := os.ListPorts(network.Uid, "network:dhcp")
	if err != nil {
		glog.Errorf("Query dhcp ports failed: %v", err)
		return err
	}
	for _, p := range networkPorts {
		dnsServers = append(dnsServers, p.FixedIPs[0].IPAddress)
	}

	// get port from opendaylight; if port doesn't exist, create a new one
	port, err := os.GetPort(portName)
	if err == ErrNotFound || port == nil {
		podHostname := strings.Split(podName, "_")[0]
		if len(podHostname) > hostnameMaxLen {
			podHostname = podHostname[:hostnameMaxLen]
		}

		// Port not found, create one
		portWithBinding, err := os.CreatePort(network.Uid, network.TenantID, portName, podHostname)
		if err != nil {
			glog.Errorf("CreatePort failed: %v", err)
			return err
		}
		port = &portWithBinding.Port
	} else if err != nil {
		glog.Errorf("GetPort failed: %v", err)
		return err
	}

	deviceOwner := fmt.Sprintf("compute:%s", getHostName())
	if port.DeviceOwner != deviceOwner {
		// Update hostname in order to make sure it is correct
		updateOpts := portsbinding.UpdateOpts{
			HostID: getHostName(),
			UpdateOptsBuilder: ports.UpdateOpts{
				DeviceOwner: deviceOwner,
			},
		}
		_, err = os.odlClient.UpdatePort(port.ID, updateOpts).Extract()
		if err != nil {
			os.odlClient.DeletePort(port.ID)
			glog.Errorf("Update port %s failed: %v", portName, err)
			return err
		}
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	// get subnet and gateway
	subnet, err := os.getProviderSubnet(port.FixedIPs[0].SubnetID)
	if err != nil {
		glog.Errorf("Get info of subnet %s failed: %v", port.FixedIPs[0].SubnetID, err)
		if nil != os.odlClient.DeletePort(port.ID).ExtractErr() {
			glog.Warningf("Delete port %s failed", port.ID)
		}
		return err
	}

	// setup interface for pod
	_, cidr, _ := net.ParseCIDR(subnet.Cidr)
	prefixSize, _ := cidr.Mask.Size()
	err = os.Plugin.SetupInterface(podName+"_"+namespace, podInfraContainerID, port,
		fmt.Sprintf("%s/%d", port.FixedIPs[0].IPAddress, prefixSize),
		subnet.Gateway, dnsServers, containerRuntime)
	if err != nil {
		glog.Errorf("SetupInterface failed: %v", err)
		if nil != os.odlClient.DeletePort(port.ID).ExtractErr() {
			glog.Warningf("Delete port %s failed", port.ID)
		}
		return err
	}

	return nil
}

// Teardown pod
func (os *OpenDaylight) TeardownPod(podName, namespace, podInfraContainerID string, network *provider.Network, containerRuntime string) error {
	portName := os.BuildPortName(podName, namespace, network.Uid)

	// get port from opendaylight
	port, err := os.GetPort(portName)
	if err != nil {
		glog.Errorf("GetPort %s failed: %v", portName, err)
		return err
	}

	if port == nil {
		glog.Warningf("Port %s already deleted", portName)
		return nil
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	// delete interface for docker
	err = os.Plugin.DestroyInterface(podName+"_"+namespace, podInfraContainerID, port, containerRuntime)
	if err != nil {
		glog.Errorf("DestroyInterface for pod %s failed: %v", podName, err)
		return err
	}

	// delete port from opendaylight
	err = os.DeletePort(portName)
	if err != nil {
		glog.Errorf("DeletePort %s failed: %v", portName, err)
		return err
	}

	return nil
}

// Status of pod
func (os *OpenDaylight) PodStatus(podName, namespace, podInfraContainerID string, network *provider.Network, containerRuntime string) (string, error) {
	ipAddress := ""
	portName := os.BuildPortName(podName, namespace, network.Uid)
	port, err := os.GetPort(portName)
	if err != nil {
		return ipAddress, err
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	if port != nil {
		ipAddress = port.FixedIPs[0].IPAddress
	}

	return ipAddress, nil
}
