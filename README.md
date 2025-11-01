[![Build Status](https://travis-ci.org/dreadl0ck/go-dpi.svg?branch=master)](https://travis-ci.org/dreadl0ck/go-dpi)
[![Coverage Status](https://coveralls.io/repos/github/dreadl0ck/go-dpi/badge.svg?branch=master)](https://coveralls.io/github/dreadl0ck/go-dpi?branch=master)
[![](https://godoc.org/github.com/dreadl0ck/go-dpi?status.svg)](https://godoc.org/github.com/dreadl0ck/go-dpi)
[![Go Report Card](https://goreportcard.com/badge/github.com/dreadl0ck/go-dpi)](https://goreportcard.com/report/github.com/dreadl0ck/go-dpi)

# go-dpi

go-dpi is an open source Go library for application layer protocol identification of traffic flows. In addition to its own heuristic methods, it contains wrappers for other popular and well-established libraries that also perform protocol identification, such as nDPI and libprotoident. It aims to provide a simple, easy-to-use interface and the capability to be extended by a developer with new detection methods and protocols.

It attempts to classify flows to different protocols regardless of the ports used. This makes it possible to detect protocols on non-standard ports, which is ideal for honeypots, as malware might often try and throw off detection methods by using non-standard and unregistered ports. Also, with its layered architecture, it aims to be fast in its detection, only using heavier classification methods when the faster ones fail.

It is being developed in the context of the Google Summer of Code 2017 program, under the mentorship of The Honeynet Project.

Please read the project's [Wiki page](https://github.com/dreadl0ck/go-dpi/wiki) for more information.

For documentation, please check out the [godoc reference](https://godoc.org/github.com/dreadl0ck/go-dpi).

## Example usage

The library and the modules APIs aim to be very simple and straightforward to use. The library relies on the [gopacket](https://godoc.org/github.com/gopacket/gopacket) library and its Packet structure. Once you have a Packet in your hands, it's very easy to classify it with the library.
First of all you need to initialize the library. You can do that by calling:
```go
godpi.Initialize()
```

The `Initialize` method initializes all the selected modules in the library, by calling the `Initialize` method that they provide. It also creates the cache that is used to track the flows, which outdates unused flows after some minutes.

Then, you need a flow that contains the packet. You can get the flow a packet belongs to with the following call:

```go
flow, isNew := godpi.GetPacketFlow(packet)
```

That call returns the flow, as well as whether that flow is a new one (this packet is the first in the flow) or an existing one.

Afterwards, classifying the flow can be done by calling:

```go
result := godpi.ClassifyFlow(flow)
```

This returns the protocol guessed by the classifiers as well as the source, e.g. go-dpi or one of the wrappers.

**Note:** The classification process is deterministic and follows a strict priority order:

1. **go-dpi classifiers** - Fast heuristic-based detection (tried first)
2. **libprotoident (LPI)** - Lightweight payload inspection (tried second)
3. **nDPI** - Deep packet inspection (tried last)

Modules are evaluated sequentially in this order, and the first successful match is returned. This ensures reproducible and predictable results across multiple runs, even when multiple classifiers could potentially match the same flow. The priority order is maintained regardless of which modules are enabled.

**Caching:** Classification results are cached in the flow object. Once a flow is successfully classified, subsequent calls to `ClassifyFlow()` return the cached result immediately without re-running classification modules. This optimization is transparent and ensures efficient processing of multiple packets from the same flow.

### Advanced: Getting All Detection Results

If you want to see what all detection engines report for a flow (useful for debugging or analysis), use:

```go
results := godpi.ClassifyFlowAllModules(flow)
```

This function:
- Runs **all** activated modules sequentially in the same priority order
- Returns all successful classifications from all modules
- **Deduplicates** results by protocol (if multiple modules detect the same protocol, only the first detection is included)
- Ensures deterministic ordering based on module priority

This is useful when you want to compare detection results across different engines or understand what protocols multiple modules are detecting.

Finally, once you are done with the library, you should free the used resources by calling:

```go
godpi.Destroy()
```

`Destroy` frees all the resources that the library is using, and calls the `Destroy` method of all the activated modules. It is essentially the opposite of the `Initialize` method.

A minimal example application is included below. It uses the library to classify a packet capture file, located at `/tmp/http.cap`. Note the helpful `godpi.ReadDumpFile` function that returns a channel with all the packets in the file.

```go
package main

import (
	"fmt"
	"github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/go-dpi/utils"
)

func main() {
	godpi.Initialize()
	defer godpi.Destroy()
	packets, err := utils.ReadDumpFile("/tmp/http.cap")
	if err != nil {
		fmt.Println(err)
	} else {
		for packet := range packets {
			flow, _ := godpi.GetPacketFlow(packet)
			result := godpi.ClassifyFlow(flow)
			if result.Protocol != types.Unknown {
				fmt.Println(result.Source, "detected protocol", result.Protocol)
			} else {
				fmt.Println("No detection was made")
			}
		}
	}
}
```

## License

go-dpi is available under the MIT license and distributed in source code format.
