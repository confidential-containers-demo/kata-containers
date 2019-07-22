// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	persistapi "github.com/kata-containers/runtime/virtcontainers/persist/api"
)

// BridgedMacvlanEndpoint represents a macvlan endpoint that is bridged to the VM
type BridgedMacvlanEndpoint struct {
	NetPair            NetworkInterfacePair
	EndpointProperties NetworkInfo
	EndpointType       EndpointType
	PCIAddr            string
}

func createBridgedMacvlanNetworkEndpoint(idx int, ifName string, interworkingModel NetInterworkingModel) (*BridgedMacvlanEndpoint, error) {
	if idx < 0 {
		return &BridgedMacvlanEndpoint{}, fmt.Errorf("invalid network endpoint index: %d", idx)
	}

	netPair, err := createNetworkInterfacePair(idx, ifName, interworkingModel)
	if err != nil {
		return nil, err
	}

	endpoint := &BridgedMacvlanEndpoint{
		NetPair:      netPair,
		EndpointType: BridgedMacvlanEndpointType,
	}
	if ifName != "" {
		endpoint.NetPair.VirtIface.Name = ifName
	}

	return endpoint, nil
}

// Properties returns properties of the interface.
func (endpoint *BridgedMacvlanEndpoint) Properties() NetworkInfo {
	return endpoint.EndpointProperties
}

// Name returns name of the veth interface in the network pair.
func (endpoint *BridgedMacvlanEndpoint) Name() string {
	return endpoint.NetPair.VirtIface.Name
}

// HardwareAddr returns the mac address that is assigned to the tap interface
// in th network pair.
func (endpoint *BridgedMacvlanEndpoint) HardwareAddr() string {
	return endpoint.NetPair.TAPIface.HardAddr
}

// Type identifies the endpoint as a virtual endpoint.
func (endpoint *BridgedMacvlanEndpoint) Type() EndpointType {
	return endpoint.EndpointType
}

// SetProperties sets the properties for the endpoint.
func (endpoint *BridgedMacvlanEndpoint) SetProperties(properties NetworkInfo) {
	endpoint.EndpointProperties = properties
}

// PciAddr returns the PCI address of the endpoint.
func (endpoint *BridgedMacvlanEndpoint) PciAddr() string {
	return endpoint.PCIAddr
}

// SetPciAddr sets the PCI address of the endpoint.
func (endpoint *BridgedMacvlanEndpoint) SetPciAddr(pciAddr string) {
	endpoint.PCIAddr = pciAddr
}

// NetworkPair returns the network pair of the endpoint.
func (endpoint *BridgedMacvlanEndpoint) NetworkPair() *NetworkInterfacePair {
	return &endpoint.NetPair
}

// Attach for virtual endpoint bridges the network pair and adds the
// tap interface of the network pair to the hypervisor.
func (endpoint *BridgedMacvlanEndpoint) Attach(h hypervisor) error {
	if err := xConnectVMNetwork(endpoint, h); err != nil {
		networkLogger().WithError(err).Error("Error bridging virtual ep")
		return err
	}

	return h.addDevice(endpoint, netDev)
}

// Detach for the virtual endpoint tears down the tap and bridge
// created for the veth interface.
func (endpoint *BridgedMacvlanEndpoint) Detach(netNsCreated bool, netNsPath string) error {
	// The network namespace would have been deleted at this point
	// if it has not been created by virtcontainers.
	if !netNsCreated {
		return nil
	}

	return doNetNS(netNsPath, func(_ ns.NetNS) error {
		return xDisconnectVMNetwork(endpoint)
	})
}

// HotAttach for physical endpoint not supported yet
func (endpoint *BridgedMacvlanEndpoint) HotAttach(h hypervisor) error {
	return fmt.Errorf("BridgedMacvlanEndpoint does not support Hot attach")
}

// HotDetach for physical endpoint not supported yet
func (endpoint *BridgedMacvlanEndpoint) HotDetach(h hypervisor, netNsCreated bool, netNsPath string) error {
	return fmt.Errorf("BridgedMacvlanEndpoint does not support Hot detach")
}

func (endpoint *BridgedMacvlanEndpoint) save() (s persistapi.NetworkEndpoint) {
	s.Type = string(endpoint.Type())
	s.BridgedMacvlan = &persistapi.BridgedMacvlanEndpoint{
		NetPair: persistapi.NetworkInterfacePair{
			TapInterface: persistapi.TapInterface{
				ID:   endpoint.NetPair.TapInterface.ID,
				Name: endpoint.NetPair.TapInterface.Name,
				TAPIface: persistapi.NetworkInterface{
					Name:     endpoint.NetPair.TapInterface.TAPIface.Name,
					HardAddr: endpoint.NetPair.TapInterface.TAPIface.HardAddr,
					Addrs:    endpoint.NetPair.TapInterface.TAPIface.Addrs,
				},
			},
			VirtIface: persistapi.NetworkInterface{
				Name:     endpoint.NetPair.VirtIface.Name,
				HardAddr: endpoint.NetPair.VirtIface.HardAddr,
				Addrs:    endpoint.NetPair.VirtIface.Addrs,
			},
			NetInterworkingModel: int(endpoint.NetPair.NetInterworkingModel),
		},
	}
	return
}

func (endpoint *BridgedMacvlanEndpoint) load(s persistapi.NetworkEndpoint) {
	endpoint.EndpointType = BridgedMacvlanEndpointType

	if s.BridgedMacvlan != nil {
		iface := s.BridgedMacvlan
		endpoint.NetPair = NetworkInterfacePair{
			TapInterface: TapInterface{
				ID:   iface.NetPair.TapInterface.ID,
				Name: iface.NetPair.TapInterface.Name,
				TAPIface: NetworkInterface{
					Name:     iface.NetPair.TapInterface.TAPIface.Name,
					HardAddr: iface.NetPair.TapInterface.TAPIface.HardAddr,
					Addrs:    iface.NetPair.TapInterface.TAPIface.Addrs,
				},
			},
			VirtIface: NetworkInterface{
				Name:     iface.NetPair.VirtIface.Name,
				HardAddr: iface.NetPair.VirtIface.HardAddr,
				Addrs:    iface.NetPair.VirtIface.Addrs,
			},
			NetInterworkingModel: NetInterworkingModel(iface.NetPair.NetInterworkingModel),
		}
	}
}
