/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package harmonystack

import (
	"net"

	"github.com/golang/glog"
	"github.com/heartlock/harmonystack/pkg/common"
	provider "github.com/heartlock/harmonystack/pkg/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// HarmonyHandler forwards requests and responses between the docker daemon and the plugin.
type HarmonyHandler struct {
	driver *common.OpenDaylight
	server *grpc.Server
}

// NewHarmonyHandler initializes the request handler with a driver implementation.
func NewHarmonyHandler(driver *common.OpenDaylight) *HarmonyHandler {
	h := &HarmonyHandler{
		driver: driver,
		server: grpc.NewServer(),
	}
	h.registerServer()
	return h
}

func (h *HarmonyHandler) Serve(addr string) error {
	glog.V(1).Infof("Starting harmonystack at %s", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		glog.Fatalf("Failed to listen: %s", addr)
		return err
	}
	return h.server.Serve(l)
}

func (h *HarmonyHandler) registerServer() {
	provider.RegisterNetworksServer(h.server, h)
	provider.RegisterPodsServer(h.server, h)
}

func (h *HarmonyHandler) Active(c context.Context, req *provider.ActiveRequest) (*provider.ActivateResponse, error) {
	glog.V(3).Infof("Activating called")

	resp := provider.ActivateResponse{
		Result: true,
	}

	return &resp, nil
}

func (h *HarmonyHandler) GetNetwork(c context.Context, req *provider.GetNetworkRequest) (*provider.GetNetworkResponse, error) {
	glog.V(4).Infof("GetNetwork with request %v", req.String())

	resp := provider.GetNetworkResponse{}
	var result *provider.Network
	var err error
	if req.Id != "" {
		result, err = h.driver.GetNetworkByID(req.Id)
	} else if req.Name != "" {
		result, err = h.driver.GetNetwork(req.Name)
	}

	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Network = result
	}

	glog.V(4).Infof("GetNetwork result %v", resp)
	return &resp, nil
}

func (h *HarmonyHandler) CreateNetwork(c context.Context, req *provider.CreateNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("CreateNetwork with request %v", req)

	resp := provider.CommonResponse{}
	err := h.driver.CreateNetwork(req.Network)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("CreateNetwork result %v", resp)
	return &resp, nil
}

func (h *HarmonyHandler) UpdateNetwork(c context.Context, req *provider.UpdateNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("UpdateNetwork with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.UpdateNetwork(req.Network)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("UpdateNetwork result %v", resp)
	return &resp, nil
}

func (h *HarmonyHandler) DeleteNetwork(c context.Context, req *provider.DeleteNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("DeleteNetwork with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.DeleteNetwork(req.NetworkName)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("DeleteNetwork result %v", resp)
	return &resp, nil
}

func (h *HarmonyHandler) SetupPod(c context.Context, req *provider.SetupPodRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("SetupPod with request %v", req.String())

	resp := provider.CommonResponse{}
	// TODO: Add hostname in SetupPod Interface
	err := h.driver.SetupPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("SetupPod failed: %v", err)
		resp.Error = err.Error()
	}

	return &resp, nil
}

func (h *HarmonyHandler) TeardownPod(c context.Context, req *provider.TeardownPodRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("TeardownPod with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.TeardownPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("TeardownPod failed: %v", err)
		resp.Error = err.Error()
	}

	return &resp, nil
}

func (h *HarmonyHandler) PodStatus(c context.Context, req *provider.PodStatusRequest) (*provider.PodStatusResponse, error) {
	glog.V(4).Infof("PodStatus with request %v", req.String())

	resp := provider.PodStatusResponse{}
	ip, err := h.driver.PodStatus(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("PodStatus failed: %v", err)
		resp.Error = err.Error()
	} else {
		resp.Ip = ip
	}

	return &resp, nil
}
