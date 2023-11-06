// Package apphelper contains a bunch of utilities for the applications of the
// benchmarking framework.
package apphelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gonum.org/v1/gonum/stat/distuv"
)

// Distribution is interface to expose different distributions.
type Distribution interface {
	Rand() float64
}

// DistParams is a structure representing various distributions.
type DistParams struct {
	Name  string `json:"distribution"`
	Mean  int64  `json:"mean"`
	Sigma int64  `json:"sigma"`
}

// NewDistribution returns an object which generates a distribution as specified by input.
func NewDistribution(dist DistParams) (Distribution, error) {
	dist.Name = strings.ToLower(dist.Name)
	switch dist.Name {
	case "normal":
		return distuv.Normal{
			Mu:    float64(dist.Mean),
			Sigma: float64(dist.Sigma),
			Src:   nil,
		}, nil

	case "poisson":
		return distuv.Poisson{
			Lambda: float64(dist.Mean),
			Src:    nil,
		}, nil

	case "log-normal":
		return distuv.LogNormal{
			Mu:    float64(dist.Mean),
			Sigma: float64(dist.Sigma),
			Src:   nil,
		}, nil

	case "exponential":
		if dist.Mean == 0 {
			return nil, errors.New("mean cannot be 0 for exponential distribution")
		}
		return distuv.Exponential{
			Rate: float64(1000000 / dist.Mean),
			Src:  nil,
		}, nil

	case "uniform":
		return distuv.Uniform{
			Min: float64(dist.Mean - dist.Sigma),
			Max: float64(dist.Mean + dist.Sigma),
			Src: nil,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported distribution name: %s", dist.Name)
	}
}

// NewDistributionFromJSON returns an object which generates a distribution
// as specified by input JSON string.
func NewDistributionFromJSON(jsonData string) (Distribution, error) {
	var d DistParams
	err := json.Unmarshal([]byte(jsonData), &d)
	if err != nil {
		return nil, err
	}
	return NewDistribution(d)
}

// NewDistParamsFromJSON returns an object returns Distribution parameters
// as specified by input JSON string.
func NewDistParamsFromJSON(jsonData string) (DistParams, error) {
	var d DistParams

	err := json.Unmarshal([]byte(jsonData), &d)

	if err != nil {
		return DistParams{}, err
	}

	_, err = NewDistribution(d)

	if err != nil {
		return DistParams{}, err
	}

	return d, nil
}
