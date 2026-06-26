package bgp

import (
	"context"
	"log"
	"net/netip"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func setupFilter(ctx context.Context, s *server.BgpServer, importFilter []string) error {
	if len(importFilter) == 0 {
		log.Printf("filter: no import filter configured, accepting all routes")
		return nil
	}

	if err := addPrefixSet(ctx, s, "import-allow", importFilter); err != nil {
		return err
	}

	policy := &api.Policy{
		Name: "import-filter",
		Statements: []*api.Statement{
			{
				Name: "accept-allowed",
				Conditions: &api.Conditions{
					PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "import-allow"},
				},
				Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			},
			{
				Name:    "reject-rest",
				Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
			},
		},
	}
	if err := s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}); err != nil {
		return err
	}

	if err := s.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          "global",
		Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		Policies:      []*api.Policy{{Name: "import-filter"}},
		DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
	}}); err != nil {
		return err
	}

	log.Printf("filter: import %d prefixes", len(importFilter))
	return nil
}

func addPrefixSet(ctx context.Context, s *server.BgpServer, name string, prefixes []string) error {
	var list []*api.Prefix
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			list = append(list, &api.Prefix{IpPrefix: p})
			continue
		}
		max := uint32(32)
		if pfx.Addr().Is6() {
			max = 128
		}
		list = append(list, &api.Prefix{
			IpPrefix:      p,
			MaskLengthMin: uint32(pfx.Bits()),
			MaskLengthMax: max,
		})
	}
	return s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        name,
		Prefixes:    list,
	}})
}
