package model

type Status string

const (
	PresentationReceived             Status = "presentation-received"
	PresentationTransmitted          Status = "presentation-transmitted"
	PresentationRejected             Status = "presentation-rejected"
	PresentationRequested            Status = "presentation-requested"
	PresentationRequestObjectFetched Status = "request-object-fetched"
)
