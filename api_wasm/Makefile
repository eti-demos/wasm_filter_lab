run: api_wasm.wasm
	envoy -c envoy.yaml

api_wasm.wasm: api_wasm.go
	tinygo build -o api_wasm.wasm -scheduler=none -target=wasi api_wasm.go
