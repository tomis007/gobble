package gobble

import (
	"fmt"
	"gobble/internal/net/gstack"
	"gobble/internal/net/gtun"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

type GobbleOptions struct {
	Drop4       bool
	Drop6       bool
	EBPFFilter  string
	PcapFile    string
	DisablePcap bool
}

func Gobble(opts GobbleOptions, args []string) error {
	if strings.HasPrefix(os.Args[0], "G0BBL3_1") {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}

		ifce, err := gtun.CreateTun("gobbleTun0")
		if err != nil {
			return err
		}
		log.Debug().Msg(fmt.Sprintf("bringing %v up", ifce.Name()))

		gtun.ConfigureTun(ifce.Name())

		gstack, err := gstack.New(gstack.GStackOptions{
			Drop4: opts.Drop4,
			Drop6: opts.Drop6,
		})
		if err != nil {
			return err
		}
		err = gstack.InitStack(ifce)
		if err != nil {
			return err
		}

		var byteCount atomic.Uint32
		if !opts.DisablePcap {
			startPcap(ifce.Name(), opts.EBPFFilter, opts.PcapFile, &byteCount)
		}

		ids := strings.Split(os.Args[0], ":")
		uid, err := strconv.Atoi(ids[1])
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(ids[2])
		if err != nil {
			return err
		}
		log.Debug().Msg(fmt.Sprintf("uid: %d gid: %d", uid, gid))

		os.Args[0] = fmt.Sprintf("G0BBL3_2:%d:%d", uid, gid)
		err = reExec(os.Args, syscall.CLONE_NEWUSER, 0, 0, uid, gid)
		if err != nil {
			return err
		}
		if !opts.DisablePcap {
			log.Info().Msg(fmt.Sprintf("wrote %d bytes to %s", byteCount.Load(), opts.PcapFile))
		}
		return nil
	} else if strings.HasPrefix(os.Args[0], "G0BBL3_2") {
		if len(args) == 0 {
			args = append(args, "/bin/bash")
			os.Setenv("PS1", "GOBBLE> ")
			log.Warn().Msg("No command specified! starting /bin/bash")
		}
		ids := strings.Split(os.Args[0], ":")
		uid, err := strconv.Atoi(ids[1])
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(ids[2])
		if err != nil {
			return err
		}

		err = syscall.Setuid(uid)
		if err != nil {
			return err
		}
		err = unix.Setgid(gid)
		if err != nil {
			return err
		}
		bcmd := exec.Command(args[0], args[1:]...)
		bcmd.Stdin = os.Stdin
		bcmd.Stdout = os.Stdout
		bcmd.Stderr = os.Stderr
		bcmd.Env = os.Environ()
		err = bcmd.Run()
		// NOTE: Even though the command has finished the pcapgo reader
		//       may still be a few packets behind on the interface
		log.Debug().Msg("waiting for pcap...")
		if zerolog.GlobalLevel() != zerolog.ErrorLevel {
			bar := progressbar.NewOptions(-1,
				progressbar.OptionEnableColorCodes(true),
				progressbar.OptionShowBytes(false),
				progressbar.OptionSetDescription("[green]INF[reset] waiting for pcap..."),
				progressbar.OptionSpinnerType(51),
			)
			bar.Add(1)
			time.Sleep(2 * time.Second)
			bar.Finish()
			fmt.Printf("\n")
		} else {
			time.Sleep(2 * time.Second)
		}
		return err
	} else {
		log.Debug().Msg("starting exec chain...")
		log.Debug().Msg(fmt.Sprintf("Current uid: %v gid: %v", os.Getuid(), os.Getgid()))
		prefixStr := fmt.Sprintf("G0BBL3_1:%d:%d", os.Getuid(), os.Getgid())
		err := reExec(append([]string{prefixStr}, os.Args[1:]...), syscall.CLONE_NEWUSER, os.Getuid(), os.Getgid(), 0, 0)
		return err
	}
}

func startPcap(ifce string, filter string, pcapfile string, byteCount *atomic.Uint32) {
	handle, err := pcap.OpenLive(ifce, 1024, true, 5*time.Millisecond)
	if err != nil {
		log.Fatal().Err(err).Msg("pcap failed!")
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		handle.Close()
		log.Fatal().Err(err).Msg("pcap failed!")
	}
	f, err := os.Create(pcapfile)
	if err != nil {
		handle.Close()
		log.Fatal().Err(err).Msg("pcap failed!")
	}
	pcapwriter := pcapgo.NewWriter(f)
	pcapwriter.WriteFileHeader(1024, layers.LinkTypeRaw)

	// Start the PCAP reader
	// NOTE: handle.ReadPacketData() was missing packets
	log.Info().Msg("gobbling pcap!")
	if len(filter) > 0 {
		log.Info().Msg(fmt.Sprintf("eBPF filter: %s", filter))
	}
	go func() {
		defer f.Close()
		defer handle.Close()
		for {
			data, ci, err := handle.ZeroCopyReadPacketData()
			if err == nil {
				pcapwriter.WritePacket(ci, data)
				num := uint32(ci.CaptureLength)
				byteCount.Add(num)
			}
		}
	}()
}

func reExec(args []string, cloneMode uintptr, uid int, gid int, ucontainerid int, gcontainerid int) error {
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = args
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneMode,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: ucontainerid,
			HostID:      uid,
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: gcontainerid,
			HostID:      gid,
			Size:        1,
		}},
	}
	log.Debug().Msg(fmt.Sprintf("running with: uid %d, gid %d", unix.Getuid(), unix.Getgid()))
	log.Debug().Msg(fmt.Sprintf("os.Args: %v", cmd.Args))
	return cmd.Run()
}
