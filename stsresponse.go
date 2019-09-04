package stsclient

import (
)

type StsResponse struct {

	payload		[]byte
}

func ParseStsResponse(responsePayload []byte) (*StsResponse) {

	stsResponse := &StsResponse{ payload: responsePayload }

	return stsResponse
}

func (resp *StsResponse) ToString() string {
	return string(resp.payload)
}
