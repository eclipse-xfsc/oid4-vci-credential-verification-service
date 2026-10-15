package model

type Status string

const (
	PresentationReceived             Status = "presentation-received"
	PresentationTransmitted          Status = "presentation-transmitted"
	PresentationRejected             Status = "presentation-rejected"
	PresentationFulfilling           Status = "presentation-fulfilling"
	PresentationRequested            Status = "presentation-requested"
	PresentationRequestObjectFetched Status = "request-object-fetched"
)
