#! /bin/zsh

kubectl delete -n httpbin-ns httpbin
kubectl apply -f ./httpbin/pod_httpbin.yaml
