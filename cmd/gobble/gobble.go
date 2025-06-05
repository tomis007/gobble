package main

import (
	"context"
	"fmt"
	"gobble/internal/gobble"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	var outfile string
	var filter string
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print the version",
	}
	cmd := &cli.Command{
		HideHelpCommand: true,
		Name:            "gobble",
		Usage:           "gobble network traffic",
		ArgsUsage:       "-- command",
		SkipFlagParsing: false,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "print debug output"},
			&cli.BoolFlag{Name: "drop6", Aliases: []string{"no6"}, Usage: "drop IPv6 connections"},
			&cli.BoolFlag{Name: "drop4", Aliases: []string{"no4"}, Usage: "drop IPv4 connections"},
			&cli.BoolFlag{Name: "disablepcap", Aliases: []string{"nopcap"}, Usage: "do not capture a pcap file"},
			&cli.BoolFlag{Name: "silent", Aliases: []string{"s"}, Usage: "silence gobble's info messages"},
			&cli.StringFlag{
				Name:        "file",
				Value:       "captured.pcap",
				Usage:       "output pcap file name",
				Destination: &outfile,
				Aliases:     []string{"w"},
			},
			&cli.StringFlag{
				Name:        "filter",
				Usage:       "eBPF filter for pcap like: \"tcp and port 80\"",
				Destination: &filter,
				Aliases:     []string{"f"},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			var opts gobble.GobbleOptions
			if cmd.Bool("verbose") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else if cmd.Bool("silent") {
				zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			}
			opts.Drop4 = cmd.Bool("drop4")
			opts.Drop6 = cmd.Bool("drop6")
			opts.DisablePcap = cmd.Bool("disablepcap")
			opts.PcapFile = cmd.String("file")
			opts.EBPFFilter = cmd.String("filter")
			if opts.Drop4 && opts.Drop6 {
				log.Fatal().Msg("dropping both IPv6 and IPv4 is not allowed...")
			}
			log.Debug().Msg(fmt.Sprintf("started main with args: %v", os.Args))
			return gobble.Gobble(opts, cmd.Args().Slice())
		},
		Version: "v1.0.0",
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("gobble error!")
	}
}
