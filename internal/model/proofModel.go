package model

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type ProofModel struct {
	Payload       []presentation.FilterResult
	SignNamespace string
	SignKey       string
	SignGroup     string
	HolderDid     string
}
