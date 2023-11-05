package apphelper

import (
	"encoding/json"
	"fmt"
)

// RPCParams describes a RPC in simulation.
type RPCParams struct {
	Type            string
	Path            string
	Arrival         DistParams
	MessageSize     DistParams
	MessageDelay    DistParams
	ProcessingDelay DistParams
	NumMessages     DistParams
	SendSize        DistParams
	Timeout         uint32
	Request         uint32
}

// RPCFromJSON parses the input JSON file to create RPCParms.
func RPCFromJSON(j string) ([]*RPCParams, error) {
	var arr []any
	if err := json.Unmarshal([]byte(j), &arr); err != nil {
		return nil, err
	}
	var rpcs []*RPCParams

	for _, rpcInfo := range arr {
		var rpc RPCParams = RPCParams{Request: 1024}
		for k, v := range rpcInfo.(map[string]any) {
			var ok bool
			var err error
			switch k {
			case "type":
				rpc.Type, ok = v.(string)
				if !ok {
					return nil, fmt.Errorf("invalid Type: rpcInfo %v", rpcInfo)
				}
			case "path":
				rpc.Path, ok = v.(string)
				if !ok {
					return nil, fmt.Errorf("invalid Path: rpcInfo %v", rpcInfo)
				}

			case "arrival-time":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.Arrival, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Arrival Time distribution: rpcInfo %v, %s", rpcInfo, err)
				}

			case "message":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.MessageSize, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Message Size distribution: rpcInfo %v, %s", rpcInfo, err)

				}

			case "message-delay":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.MessageDelay, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Message Delay distribution: rpcInfo %v, %s", rpcInfo, err)

				}

			case "processing-delay":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.ProcessingDelay, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Processing Delay distribution: rpcInfo %v, %s", rpcInfo, err)
				}

			case "num-messages":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.NumMessages, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Num Messages distribution: rpcInfo %v, %s", rpcInfo, err)
				}

			case "send-size":
				str, _ := json.Marshal(v) // never returns non-nil err because json.Unmarshal was called above successfully
				rpc.SendSize, err = NewDistParamsFromJSON(string(str))
				if err != nil {
					return nil, fmt.Errorf("invalid Num Messages distribution: rpcInfo %v, %s", rpcInfo, err)
				}

			case "timeout":
				timeout, ok := v.(float64)
				if !ok {
					return nil, fmt.Errorf("invalid timeout: rpcInfo %v", rpcInfo)
				}
				rpc.Timeout = uint32(timeout)

			case "request-size":
				request, ok := v.(float64)
				if !ok {
					return nil, fmt.Errorf("invalid request: rpcInfo %v", rpcInfo)
				}
				rpc.Request = uint32(request)

			default:
				return nil, fmt.Errorf("unknown section in input file")
			}
		}

		if rpc.Type == "" || rpc.Path == "" || rpc.Arrival == (DistParams{}) || rpc.MessageSize == (DistParams{}) || rpc.ProcessingDelay == (DistParams{}) || rpc.Timeout == 0 {
			return nil, fmt.Errorf("rpc %v missing important parameters", rpcInfo)
		}
		rpcs = append(rpcs, &rpc)

	}
	return rpcs, nil
}
