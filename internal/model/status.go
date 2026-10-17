package model

type Status string

const (
	ConsentManual    = "manual"
	ConsentAuto      = "auto"
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusCompleted  = "completed"
	StatusRejected   = "rejected"
	StatusFailed     = "failed"
	StatusBlocked    = "blocked"
)

const (
	PresentationReceived             Status = "presentation-received"
	PresentationTransmitted          Status = "presentation-transmitted"
	PresentationRejected             Status = "presentation-rejected"
	PresentationFulfilling           Status = "presentation-fulfilling"
	PresentationRequested            Status = "presentation-requested"
	PresentationRequestObjectFetched Status = "request-object-fetched"
)
