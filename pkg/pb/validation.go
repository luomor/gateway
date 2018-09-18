package pb

import (
	"fmt"
	"regexp"

	"github.com/fagongzi/gateway/pkg/pb/metapb"
)

// ValidateRouting validate routing
func ValidateRouting(value *metapb.Routing) error {
	if value.API == 0 {
		return fmt.Errorf("missing api")
	}

	if value.ClusterID == 0 {
		return fmt.Errorf("missing cluster")
	}

	if value.Name == "" {
		return fmt.Errorf("missing name")
	}

	if value.TrafficRate <= 0 || value.TrafficRate > 100 {
		return fmt.Errorf("error traffic rate: %d", value.TrafficRate)
	}

	return nil
}

// ValidateCluster validate cluster
func ValidateCluster(value *metapb.Cluster) error {
	if value.Name == "" {
		return fmt.Errorf("missing name")
	}

	return nil
}

// ValidateServer validate server
func ValidateServer(value *metapb.Server) error {
	if value.Addr == "" {
		return fmt.Errorf("missing server address")
	}

	if value.MaxQPS == 0 {
		return fmt.Errorf("missing server max qps")
	}

	return nil
}

// ValidateAPI validate api
func ValidateAPI(value *metapb.API) error {
	if value.Name == "" {
		return fmt.Errorf("missing api name")
	}

	if value.URLPattern != "" {
		if _, err := regexp.Compile(value.URLPattern); err != nil {
			return err
		}
	}

	return nil
}
