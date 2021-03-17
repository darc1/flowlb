#!/bin/bash

go get -u github.com/jteeuwen/go-bindata/...
~/go/bin/go-bindata -pkg lb bpf/ 
