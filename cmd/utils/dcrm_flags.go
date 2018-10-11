// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package utils

import (
	"path/filepath"
	"github.com/fusion/go-fusion/node"
	"gopkg.in/urfave/cli.v1"
)

var (
	VersionEnabledFlag = cli.BoolFlag{
		Name:  "v",
		Usage: "show build version.",
	}
)

func ShowVer(ctx *cli.Context) bool {
    if ctx.GlobalBool(VersionEnabledFlag.Name) {
	return true
    }

    return false
}

func SetDcrmNodeConfig(ctx *cli.Context, cfg *node.Config) {
    SetP2PConfig(ctx, &cfg.P2P)
	setIPC(ctx, cfg)
	setHTTP(ctx, cfg)
	setWS(ctx, cfg)
	setNodeUserIdent(ctx, cfg)

	switch {
	case ctx.GlobalIsSet(DataDirFlag.Name):
		cfg.DataDir = ctx.GlobalString(DataDirFlag.Name)
	case ctx.GlobalBool(DeveloperFlag.Name):
		cfg.DataDir = "" // unless explicitly requested, use memory databases
	case ctx.GlobalBool(TestnetFlag.Name):
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "testnet")
	case ctx.GlobalBool(RinkebyFlag.Name):
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "rinkeby")
	}

	cfg.DataDir = "" //tmp

	if ctx.GlobalIsSet(KeyStoreDirFlag.Name) {
		cfg.KeyStoreDir = ctx.GlobalString(KeyStoreDirFlag.Name)
	}
	if ctx.GlobalIsSet(LightKDFFlag.Name) {
		cfg.UseLightweightKDF = ctx.GlobalBool(LightKDFFlag.Name)
	}
	if ctx.GlobalIsSet(NoUSBFlag.Name) {
		cfg.NoUSB = ctx.GlobalBool(NoUSBFlag.Name)
	}
}

// NewFusionDcrmApp creates an app with sane defaults.
func NewFusionDcrmApp(gitCommit, usage string) *cli.App {
	app := cli.NewApp()
	app.Name = "FusionDcrm"//filepath.Base(os.Args[0])
	app.Author = "caihaijun"
	//app.Authors = nil
	app.Email = "caihaijun@fusion.org"
	app.Version = "3.0.5"
	if len(gitCommit) >= 8 {
		app.Version += "-" + gitCommit[:8]
	}
	app.Usage = usage
	return app
}

