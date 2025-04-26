package model

import "gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"

type ProofModel struct {
	Payload       []presentation.FilterResult
	SignNamespace string
	SignKey       string
	SignGroup     string
	HolderDid     string
}
