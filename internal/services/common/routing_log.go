package common

import (
	app "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
)

// LogRouting accepts routing identifiers only. Never pass payloads, state tokens,
// nonces, URLs, credentials, configuration or downstream error text here.
func LogRouting(stage, tenantID, groupID, requestID, namespace, keyGroup, keyID string, failed bool) {
	app.GetEnvironment().GetLogger().Info("OID4VP routing", "stage", stage,
		"tenantId", tenantID, "groupId", groupID, "requestId", requestID,
		"namespace", namespace, "keyGroup", keyGroup, "keyId", keyID, "failed", failed)
}
