package apphelper

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDistribution(t *testing.T) {
	dists := []string{"poisson", "Exponential", "log-normal", "normal"}
	for _, name := range dists {
		input := fmt.Sprintf(`{"distribution":%q,
		"mean": 10000,
		"sigma": 1000
		}`, name)
		r, err := NewDistributionFromJSON(input)
		if err != nil {
			t.Errorf("%s:NewDistributionFromJSON(%v) returned unexpected error %v", name, input, err)
			continue
		}
		for i := 0; i < 10; i++ {
			if r.Rand() == 0 {
				t.Errorf("%s:Rand is not generating numbers", name)
			}
		}
	}
}

func TestRPCParser(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []*RPCParams
		wantErr bool
	}{
		{
			name: "Streaming Parsing",
			data: `[
    {
        "path" : "Streaming",
				"timeout" : 1000,
				"request-size":9999,
        "arrival-time" : {
            "distribution":"poisson",
            "mean":1000
        },
        "message":{
            "distribution":"normal",
            "mean":1000,
            "sigma":100
        },
        "message-delay":{
            "distribution":"poisson",
            "mean":10
        },
        "processing-delay" :{
            "distribution":"poisson",
            "mean":200
        },
        "num-messages":{
            "distribution":"normal",
            "mean":8,
            "sigma":0
        }
    }
    ]`,
			want: []*RPCParams{
				{
					Path:    "Streaming",
					Timeout: 1000,
					Request: 9999,
					Arrival: DistParams{
						Name: "poisson",
						Mean: 1000,
					},
					MessageSize: DistParams{
						Name:  "normal",
						Mean:  1000,
						Sigma: 100,
					},
					MessageDelay: DistParams{
						Name: "poisson",
						Mean: 10,
					},
					ProcessingDelay: DistParams{
						Name: "poisson",
						Mean: 200,
					},
					NumMessages: DistParams{
						Name:  "normal",
						Mean:  8,
						Sigma: 0,
					},
				},
			},
		},
		{
			name: "Unary Parsing",
			data: `[
{
    "path" : "unary",
		"timeout":1000,
    "arrival-time" : {
        "distribution":"poisson",
        "mean":1000
    },
    "message":{
        "distribution":"normal",
        "mean":100,
        "sigma":10
    },
    "processing-delay" :{
        "distribution":"normal",
        "mean":100,
        "sigma":10
    }
}
]`,
			want: []*RPCParams{
				{
					Path:    "unary",
					Timeout: 1000,
					Request: 1024,
					Arrival: DistParams{
						Name: "poisson",
						Mean: 1000,
					},
					MessageSize: DistParams{
						Name:  "normal",
						Mean:  100,
						Sigma: 10,
					},
					ProcessingDelay: DistParams{
						Name:  "normal",
						Mean:  100,
						Sigma: 10,
					},
				},
			},
		},
		{
			name: "Invalid Parsing",
			data: `[
		{
    	"path" : "unary",
    	"invalid" : {
      	  "distribution":"poisson",
        	"mean":1000
    	}
		}
		]`,
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid Dist",
			data: `[
		{
    	"path" : "unary",
    	"message" : {
      	  "distribution":"invalid",
        	"mean":1000
    	}
		}
		]`,
			want:    nil,
			wantErr: true,
		},
		{
			name: "Incomplete",
			data: `[
		{
    	"path" : "unary",
    	"message" : {
      	  "distribution":"poisson",
        	"mean":1000
    	}
		}
		]`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, test := range tests {
		rpcparams, err := RPCFromJSON(test.data)

		if test.wantErr != (err != nil) {
			t.Errorf("%s:RPCFromJSON(%v) error want error %v got %v", test.name, test.data, test.wantErr, err)
			continue
		}

		if diff := cmp.Diff(test.want, rpcparams, protocmp.Transform()); diff != "" {
			t.Errorf("RPCFromJSON(%v): returned unexpected diff (-want +got):\n%s", test.data, diff)
		}
	}
}
