api_wasm.wasm: api_wasm.go
	tinygo build -o api_wasm.wasm -scheduler=none -target=wasi api_wasm.go
	kubectl delete configmap -n httpbin-ns wasm-filter
	kubectl create configmap -n httpbin-ns wasm-filter --from-file=api_wasm.wasm

