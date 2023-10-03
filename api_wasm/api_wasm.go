// Copyright © 2021 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    // "encoding/base64"
    "encoding/binary"
    "fmt"
    // "net/url"
    // "strings"
    "unsafe"

    // "github.com/valyala/fastjson"

    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// This was taken from APIClarity generated telemetry client api.
// We cant import this module from there since it includes package net which is not supported yet by tinygo.
type Telemetry struct {
    DestinationAddress   string    `json:"destinationAddress,omitempty"`
    DestinationNamespace string    `json:"destinationNamespace,omitempty"`
    Request              *Request  `json:"request,omitempty"`
    RequestID            string    `json:"requestID,omitempty"`
    Response             *Response `json:"response,omitempty"`
    Scheme               string    `json:"scheme,omitempty"`
    SourceAddress        string    `json:"sourceAddress,omitempty"`
}

type Request struct {
    Common *Common `json:"common,omitempty"`
    Host   string  `json:"host,omitempty"`
    Method string  `json:"method,omitempty"`
    Path   string  `json:"path,omitempty"`
}

type Response struct {
    Common     *Common `json:"common,omitempty"`
    StatusCode string  `json:"statusCode,omitempty"`
}

type Common struct {
    TruncatedBody bool      `json:"TruncatedBody,omitempty"`
    Body          string    `json:"body,omitempty"`
    Headers       []*Header `json:"headers"`
    Version       string    `json:"version,omitempty"`
    Time          int64     `json:"time,omitempty"`
}

type Header struct {
    Key   string `json:"key,omitempty"`
    Value string `json:"value,omitempty"`
}

var nativeEndian binary.ByteOrder

const (
    tickMilliseconds           uint32 = 60000 // 1 Minute
    statusCodePseudoHeaderName        = ":status"
    contentTypeHeaderName             = "content-type"
    defaultServiceMesh                = "istio"
)

func main() {
    proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
    types.DefaultVMContext
}

func (*vmContext) NewPluginContext(_ uint32) types.PluginContext {
    if err := setEndianness(); err != nil {
            proxywasm.LogErrorf("Failed to set endianness: %v", err)
    }
    proxywasm.LogInfof("Starting a PluginContext")
    return &pluginContext{}
}

type pluginContext struct {
    types.DefaultPluginContext
    pluginConfig
    getDestinationNamespaceFn func(ctx *TraceFilterContext) (string, error)
}

type pluginConfig struct {
    serverAddress string // The server to which the traces will be sent
    // traceSamplingEnabled bool
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	// proxywasm.LogDebugf("Called new http context. contextID: %v", contextID)
	proxywasm.LogInfof("Called new http context. contextID: %v", contextID)

	return &TraceFilterContext{
		contextID:                 contextID,
		serverAddress:             ctx.serverAddress,
		// hostsToTrace:              ctx.hostsToTrace,
		// traceSamplingEnabled:      ctx.traceSamplingEnabled,
		getDestinationNamespaceFn: ctx.getDestinationNamespaceFn,
		Telemetry: Telemetry{
			Request: &Request{
				Common: &Common{
					Headers: []*Header{},
				},
			},
			Response: &Response{
				Common: &Common{
					Headers: []*Header{},
				},
			},
		},
	}
}


type TraceFilterContext struct {
    types.DefaultHttpContext
    totalRequestBodySize  int
    totalResponseBodySize int
    skipStream            bool
    contextID             uint32
    rootContextID         uint32
    destinationPort       string
    // The server to which the traces will be sent
    serverAddress string

    Telemetry

    // traceSamplingEnabled      bool
    // hostsToTrace              map[string]struct{}
    isHostFixed               bool
    getDestinationNamespaceFn func(ctx *TraceFilterContext) (string, error)
}

func (ctx *pluginContext) OnPluginStart(_ int) types.OnPluginStartStatus {
    ctx.pluginConfig = pluginConfig{serverAddress: "web_log"}

    ctx.getDestinationNamespaceFn = getDestinationNamespace

	return types.OnPluginStartStatusOK
}

func getDestinationNamespace(ctx *TraceFilterContext) (string, error) {
	return "", nil
}

func setEndianness() error {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		nativeEndian = binary.LittleEndian
		return fmt.Errorf("could not determine native endianness")
	}
	return nil
}
