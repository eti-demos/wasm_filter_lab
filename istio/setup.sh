#! /bin/zsh

kind create cluster --config ./kind/kind-config.yaml

wait 5
istioctl install --set profile=demo --skip-confirmation


# Need to add the configMap for wasm filter 
