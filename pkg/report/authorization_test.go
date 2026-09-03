package report

import (
	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/types"
	"testing"
)

func TestBuildAuthorizationJSONExposesVersionedFacts(t *testing.T) {
	db, err := builder.New().Build([]*types.SourceFile{{Path: "/tmp/AuthReport.sol", Content: `pragma solidity ^0.8.20; contract AuthReport { address owner; function withdraw() external { require(msg.sender == owner); } }`}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	doc := BuildAuthorizationJSON(db)
	if !doc.Available || doc.FactsVersion != types.AuthorizationFactsVersion || doc.Count != 1 {
		t.Fatalf("authorization artifact = %+v", doc)
	}
	if doc.Facts[0].Verdict != types.AuthorizationProtected {
		t.Fatalf("fact = %+v", doc.Facts[0])
	}
}
