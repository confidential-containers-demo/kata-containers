//go:build linux
// +build linux

// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bytes"
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/simple-kbs"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/intel-go/cpuid"
	govmmQemu "github.com/kata-containers/kata-containers/src/runtime/pkg/govmm/qemu"
)

type qemuAmd64 struct {
	// inherit from qemuArchBase, overwrite methods if needed
	qemuArchBase

	vmFactory bool

	devLoadersCount uint32

	sgxEPCSize int64
}

const (
	defaultQemuPath = "/usr/bin/qemu-system-x86_64"

	defaultQemuMachineType = QemuQ35

	defaultQemuMachineOptions = "accel=kvm,kernel_irqchip=on"

	qmpMigrationWaitTimeout = 5 * time.Second

	sevAttestationGrpcTimeout     = 10 * time.Second
	sevAttestationWorkingDir      = "/opt/sev/"
	sevAttestationCertChainName   = "cert_chain.cert"
	sevAttestationGodhName        = "godh.bin"
	sevAttestationSessionFileName = "session_file.bin"
)

var qemuPaths = map[string]string{
	QemuQ35:     defaultQemuPath,
	QemuMicrovm: defaultQemuPath,
}

var kernelParams = []Param{
	{"tsc", "reliable"},
	{"no_timer_check", ""},
	{"rcupdate.rcu_expedited", "1"},
	{"i8042.direct", "1"},
	{"i8042.dumbkbd", "1"},
	{"i8042.nopnp", "1"},
	{"i8042.noaux", "1"},
	{"noreplace-smp", ""},
	{"reboot", "k"},
	{"console", "hvc0"},
	{"console", "hvc1"},
	{"cryptomgr.notests", ""},
	{"net.ifnames", "0"},
	{"pci", "lastbus=0"},
}

var supportedQemuMachines = []govmmQemu.Machine{
	{
		Type:    QemuQ35,
		Options: defaultQemuMachineOptions,
	},
	{
		Type:    QemuVirt,
		Options: defaultQemuMachineOptions,
	},
	{
		Type:    QemuMicrovm,
		Options: defaultQemuMachineOptions,
	},
}

func newQemuArch(config HypervisorConfig) (qemuArch, error) {
	machineType := config.HypervisorMachineType
	if machineType == "" {
		machineType = defaultQemuMachineType
	}

	var mp *govmmQemu.Machine
	for _, m := range supportedQemuMachines {
		if m.Type == machineType {
			mp = &m
			break
		}
	}
	if mp == nil {
		return nil, fmt.Errorf("unrecognised machinetype: %v", machineType)
	}

	factory := false
	if config.BootToBeTemplate || config.BootFromTemplate {
		factory = true
	}

	// IOMMU and Guest Protection require a split IRQ controller for handling interrupts
	// otherwise QEMU won't be able to create the kernel irqchip
	if config.IOMMU || config.ConfidentialGuest {
		mp.Options = "accel=kvm,kernel_irqchip=split"
	}

	if config.IOMMU {
		kernelParams = append(kernelParams,
			Param{"intel_iommu", "on"})
		kernelParams = append(kernelParams,
			Param{"iommu", "pt"})
	}

	q := &qemuAmd64{
		qemuArchBase: qemuArchBase{
			qemuMachine:          *mp,
			qemuExePath:          qemuPaths[machineType],
			memoryOffset:         config.MemOffset,
			kernelParamsNonDebug: kernelParamsNonDebug,
			kernelParamsDebug:    kernelParamsDebug,
			kernelParams:         kernelParams,
			disableNvdimm:        config.DisableImageNvdimm,
			dax:                  true,
			protection:           noneProtection,
		},
		vmFactory: factory,
	}

	if config.ConfidentialGuest {
		if err := q.enableProtection(); err != nil {
			return nil, err
		}

		if !q.qemuArchBase.disableNvdimm {
			hvLogger.WithField("subsystem", "qemuAmd64").Warn("Nvdimm is not supported with confidential guest, disabling it.")
			q.qemuArchBase.disableNvdimm = true
		}
	}

	if config.SGXEPCSize != 0 {
		q.sgxEPCSize = config.SGXEPCSize
		if q.qemuMachine.Options != "" {
			q.qemuMachine.Options += ","
		}
		// qemu sandboxes will only support one EPC per sandbox
		// this is because there is only one annotation (sgx.intel.com/epc)
		// to specify the size of the EPC.
		q.qemuMachine.Options += "sgx-epc.0.memdev=epc0,sgx-epc.0.node=0"
	}

	q.handleImagePath(config)

	return q, nil
}

func (q *qemuAmd64) capabilities() types.Capabilities {
	var caps types.Capabilities

	if q.qemuMachine.Type == QemuQ35 ||
		q.qemuMachine.Type == QemuVirt {
		caps.SetBlockDeviceHotplugSupport()
	}

	caps.SetMultiQueueSupport()
	caps.SetFsSharingSupport()

	return caps
}

func (q *qemuAmd64) bridges(number uint32) {
	q.Bridges = genericBridges(number, q.qemuMachine.Type)
}

func (q *qemuAmd64) cpuModel() string {
	cpuModel := defaultCPUModel

	// VMX is not migratable yet.
	// issue: https://github.com/kata-containers/runtime/issues/1750
	if q.vmFactory {
		hvLogger.WithField("subsystem", "qemuAmd64").Warn("VMX is not migratable yet: turning it off")
		cpuModel += ",vmx=off"
	}

	return cpuModel
}

func (q *qemuAmd64) memoryTopology(memoryMb, hostMemoryMb uint64, slots uint8) govmmQemu.Memory {
	return genericMemoryTopology(memoryMb, hostMemoryMb, slots, q.memoryOffset)
}

// Is Memory Hotplug supported by this architecture/machine type combination?
func (q *qemuAmd64) supportGuestMemoryHotplug() bool {
	// true for all amd64 machine types except for microvm.
	if q.qemuMachine.Type == govmmQemu.MachineTypeMicrovm {
		return false
	}

	return q.protection == noneProtection
}

func (q *qemuAmd64) appendImage(ctx context.Context, devices []govmmQemu.Device, path string) ([]govmmQemu.Device, error) {
	if !q.disableNvdimm {
		return q.appendNvdimmImage(devices, path)
	}
	return q.appendBlockImage(ctx, devices, path)
}

// enable protection
func (q *qemuAmd64) enableProtection() error {
	var err error
	q.protection, err = availableGuestProtection()
	if err != nil {
		return err
	}
	logger := hvLogger.WithFields(logrus.Fields{
		"subsystem":               "qemuAmd64",
		"machine":                 q.qemuMachine,
		"kernel-params-debug":     q.kernelParamsDebug,
		"kernel-params-non-debug": q.kernelParamsNonDebug,
		"kernel-params":           q.kernelParams})

	switch q.protection {
	case tdxProtection:
		if q.qemuMachine.Options != "" {
			q.qemuMachine.Options += ","
		}
		q.qemuMachine.Options += "kvm-type=tdx,confidential-guest-support=tdx"
		q.kernelParams = append(q.kernelParams, Param{"tdx_guest", ""})
		logger.Info("Enabling TDX guest protection")
		return nil
	case sevProtection:
		if q.qemuMachine.Options != "" {
			q.qemuMachine.Options += ","
		}
		q.qemuMachine.Options += "confidential-guest-support=sev"
		logger.Info("Enabling SEV guest protection")
		return nil

	// TODO: Add support for other x86_64 technologies

	default:
		return fmt.Errorf("This system doesn't support Confidential Computing (Guest Protection)")
	}
}

// append protection device
func (q *qemuAmd64) appendProtectionDevice(devices []govmmQemu.Device, firmware, firmwareVolume string) ([]govmmQemu.Device, string, error) {
	if q.sgxEPCSize != 0 {
		devices = append(devices,
			govmmQemu.Object{
				Type:     govmmQemu.MemoryBackendEPC,
				ID:       "epc0",
				Prealloc: true,
				Size:     uint64(q.sgxEPCSize),
			})
	}

	switch q.protection {
	case tdxProtection:
		id := q.devLoadersCount
		q.devLoadersCount += 1
		return append(devices,
			govmmQemu.Object{
				Driver:         govmmQemu.Loader,
				Type:           govmmQemu.TDXGuest,
				ID:             "tdx",
				DeviceID:       fmt.Sprintf("fd%d", id),
				Debug:          false,
				File:           firmware,
				FirmwareVolume: firmwareVolume,
			}), "", nil
	case noneProtection:
		return devices, firmware, nil

	default:
		return devices, "", fmt.Errorf("Unsupported guest protection technology: %v", q.protection)
	}
}

// Add the SEV Object parameters for sev guest protection and conditionally
// for SEV pre-attestation
func (q *qemuAmd64) appendSEVObject(devices []govmmQemu.Device, firmware, firmwareVolume string, policy uint32, attestationId string) ([]govmmQemu.Device, string, error) {
	attestationDataPath := sevAttestationWorkingDir + attestationId

	godhPath := attestationDataPath + sevAttestationGodhName
	sessionFilePath := attestationDataPath + sevAttestationSessionFileName

	// If attestation is enabled, add the certfile and session file
	// and the kernel hashes flag.
	if len(attestationId) > 0 {
		return append(devices,
			govmmQemu.Object{
				Type:            govmmQemu.SEVGuest,
				ID:              "sev",
				Debug:           false,
				File:            firmware,
				CBitPos:         cpuid.AMDMemEncrypt.CBitPosition,
				ReducedPhysBits: cpuid.AMDMemEncrypt.PhysAddrReduction,
				SevPolicy:       policy,
				CertFilePath:    godhPath,
				SessionFilePath: sessionFilePath,
				KernelHashes:    true,
			}), "", nil
	} else {
		return append(devices,
			govmmQemu.Object{
				Type:            govmmQemu.SEVGuest,
				ID:              "sev",
				Debug:           false,
				File:            firmware,
				CBitPos:         cpuid.AMDMemEncrypt.CBitPosition,
				ReducedPhysBits: cpuid.AMDMemEncrypt.PhysAddrReduction,
				SevPolicy:       policy,
			}), "", nil
	}
}

// setup prelaunch attestation
func (q *qemuArchBase) setupSEVGuestAttestation(ctx context.Context,
	proxy string,
	policy uint32) (string, error) {

	logger := virtLog.WithField("subsystem", "SEV attestation")
	logger.Info("Set up prelaunch attestation")

	certChainBin, err := os.ReadFile(sevAttestationWorkingDir + sevAttestationCertChainName)
	certChain := b64.StdEncoding.EncodeToString([]byte(certChainBin))

	if err != nil {
		log.Fatalf("cert chain not found: %v", err)
	}

	conn, err := grpc.Dial(proxy, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	client := pb.NewKeyBrokerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	request := pb.BundleRequest{
		CertificateChain: string(certChain),
		Policy:           policy,
	}
	bundleResponse, err := client.GetBundle(ctx, &request)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	attestationId := bundleResponse.LaunchId
	attestationDataPath := sevAttestationWorkingDir + attestationId
	_ = os.Mkdir(attestationDataPath, os.ModePerm)

	godhPath := attestationDataPath + sevAttestationGodhName
	sessionFilePath := attestationDataPath + sevAttestationSessionFileName

	_ = os.WriteFile(godhPath, []byte(bundleResponse.GuestOwnerPublicKey), 0777)
	_ = os.WriteFile(sessionFilePath, []byte(bundleResponse.LaunchBlob), 0777)

	return attestationId, nil
}

type guidLE [16]byte

// The following definitions must be identical to those in QEMU target/i386/sev.c

// GUID: 9438d606-4f22-4cc9-b479-a793d411fd21
var sevHashTableHeaderGuid = guidLE{0x06, 0xd6, 0x38, 0x94, 0x22, 0x4f, 0xc9, 0x4c, 0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21}

// GUID: 4de79437-abd2-427f-b835-d5b172d2045b
var sevKernelEntryGuid = guidLE{0x37, 0x94, 0xe7, 0x4d, 0xd2, 0xab, 0x7f, 0x42, 0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b}

// GUID: 44baf731-3a2f-4bd7-9af1-41e29169781d
var sevInitrdEntryGuid = guidLE{0x31, 0xf7, 0xba, 0x44, 0x2f, 0x3a, 0xd7, 0x4b, 0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d}

// GUID: 97d02dd8-bd20-4c94-aa78-e7714d36ab2a
var sevCmdlineEntryGuid = guidLE{0xd8, 0x2d, 0xd0, 0x97, 0x20, 0xbd, 0x94, 0x4c, 0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a}

type sevHashTableEntry struct {
	entryGuid guidLE
	length    uint16
	hash      [sha256.Size]byte
}

type sevHashTable struct {
	tableGuid guidLE
	length    uint16
	cmdline   sevHashTableEntry
	initrd    sevHashTableEntry
	kernel    sevHashTableEntry
}

type paddedSevHashTable struct {
	table   sevHashTable
	padding [8]byte
}

func fileSha256(filename string) (res [sha256.Size]byte, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return res, err
	}
	defer f.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return res, err
	}

	copy(res[:], digest.Sum(nil))
	return res, nil
}

func constructSevHashesTable(kernelPath, initrdPath, cmdline string) ([]byte, error) {
	kernelHash, err := fileSha256(kernelPath)
	if err != nil {
		return []byte{}, err
	}

	initrdHash, err := fileSha256(initrdPath)
	if err != nil {
		return []byte{}, err
	}

	cmdlineHash := sha256.Sum256(append([]byte(cmdline), 0))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, sevHashTableEntry{})
	if err != nil {
		return []byte{}, err
	}
	entrySize := uint16(buf.Len())

	buf = new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, sevHashTable{})
	if err != nil {
		return []byte{}, err
	}
	tableSize := uint16(buf.Len())

	ht := paddedSevHashTable{
		table: sevHashTable{
			tableGuid: sevHashTableHeaderGuid,
			length:    tableSize,
			cmdline: sevHashTableEntry{
				entryGuid: sevCmdlineEntryGuid,
				length:    entrySize,
				hash:      cmdlineHash,
			},
			initrd: sevHashTableEntry{
				entryGuid: sevInitrdEntryGuid,
				length:    entrySize,
				hash:      initrdHash,
			},
			kernel: sevHashTableEntry{
				entryGuid: sevKernelEntryGuid,
				length:    entrySize,
				hash:      kernelHash,
			},
		},
		padding: [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	htBuf := new(bytes.Buffer)
	err = binary.Write(htBuf, binary.LittleEndian, ht)
	if err != nil {
		return []byte{}, err
	}
	return htBuf.Bytes(), nil
}

func calculateSevLaunchDigest(firmwarePath, kernelPath, initrdPath, cmdline string) (res [sha256.Size]byte, err error) {
	f, err := os.Open(firmwarePath)
	if err != nil {
		return res, err
	}
	defer f.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return res, err
	}

	ht, err := constructSevHashesTable(kernelPath, initrdPath, cmdline)
	if err != nil {
		return res, err
	}
	digest.Write(ht)

	copy(res[:], digest.Sum(nil))
	return res, nil
}

// wait for prelaunch attestation to complete
func (q *qemuArchBase) sevGuestAttestation(ctx context.Context,
	qmp *govmmQemu.QMP,
	proxy string,
	policy uint32,
	keyset string,
	attestationId string,
	kernelPath string,
	initrdPath string,
	fwPath string,
	kernelParameters string) error {

	switch q.protection {
	case sevProtection:
		logger := virtLog.WithField("subsystem", "SEV attestation")
		logger.Info("Processing prelaunch attestation")

		// Pull the launch measurement from VM
		launchMeasure, err := qmp.ExecuteQuerySEVLaunchMeasure(ctx)
		qemuSevInfo, err := qmp.ExecuteQuerySEV(ctx)

		if err != nil {
			return err
		}

		// gRPC connection
		conn, err := grpc.Dial(proxy, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}

		client := pb.NewKeyBrokerServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		requestDetails := pb.RequestDetails{
			Guid:       "0a46e24d-478c-4eb1-8696-113eeec3aa99", // hardcoded secret guid
			Format:     "JSON",
			SecretType: "bundle",
			Id:         keyset,
		}

		var secrets []*pb.RequestDetails
		secrets = append(secrets, &requestDetails)

		launchDigest, err := calculateSevLaunchDigest(fwPath, kernelPath, initrdPath, kernelParameters)
		if err != nil {
			log.Fatalf("can't calculate SEV launch digest: %v", err)
		}
		launchDigestBase64 := b64.StdEncoding.EncodeToString(launchDigest[:])

		request := pb.SecretRequest{
			LaunchMeasurement: launchMeasure.Measurement,
			LaunchId:          attestationId,        // stored from bundle request
			Policy:            policy,               // Stored from startup
			ApiMajor:          qemuSevInfo.APIMajor, // from qemu.SEVInfo
			ApiMinor:          qemuSevInfo.APIMinor,
			BuildId:           qemuSevInfo.BuildId,
			FwDigest:          launchDigestBase64,
			LaunchDescription: "shim launch",
			SecretRequests:    secrets,
		}
		logger.Info("requesting secrets")
		secretResponse, err := client.GetSecret(ctx, &request)
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}

		logger.Info("secrets acquired")

		secretHeader := secretResponse.LaunchSecretHeader
		secret := secretResponse.LaunchSecretData

		// Inject secret into VM
		if err := qmp.ExecuteSEVInjectLaunchSecret(ctx, secretHeader, secret); err != nil {
			return err
		}
		logger.Info("secrets injected")
		// Continue the VM
		return qmp.ExecuteCont(ctx)
	default:
		return nil
	}
}
