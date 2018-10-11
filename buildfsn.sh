#!/bin/sh

#Copyright 2018 The fusion-dcrm 
#Author: caihaijun@fusion.org

#build/env.sh /usr/lib/golang/bin/go install -a -gcflags '-N -l' -v ./cmd/geth

#ubuntu
#build/env.sh /opt/go/bin/go install -a -gcflags '-N -l' -v ./cmd/bootnode
#build/env.sh /opt/go/bin/go install -a -gcflags '-N -l' -v ./cmd/fusion-dcrm
build/env.sh /opt/go/bin/go install -a -gcflags '-N -l' -v ./cmd/gfsn
