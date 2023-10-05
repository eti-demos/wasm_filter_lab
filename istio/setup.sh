#! /bin/zsh

kind create cluster --config ./kind/kind-config.yaml

wait 5
istioctl install --set profile=demo --skip-confirmation

