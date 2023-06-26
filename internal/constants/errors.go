package constants

import "errors"

var (
	ErrorNotFound               = errors.New("not found")
	ErrorInputInvalid           = errors.New("input invalid")
	ErrorCertTTLShorterThanHalf = errors.New("cert ttl too short, less than ttl/2 left")
)

var (
	ErrorGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	ErrorHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	ErrorHealthCheckerCheck   = errors.New("healthcheck failed")
)
