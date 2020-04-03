package metadata

import (
	"github.com/0xkraken/incognito-sdk-golang/common"
	"strconv"
)

type PortalExchangeRates struct {
	MetadataBase
	SenderAddress string
	Rates         []*ExchangeRateInfo //amount * 10^6 (USDT)
}

type PortalExchangeRatesAction struct {
	Meta     PortalExchangeRates
	TxReqID  common.Hash
	LockTime int64
	ShardID  byte
}

type ExchangeRateInfo struct {
	PTokenID string
	Rate     uint64
}

type ExchangeRatesRequestStatus struct {
	Status byte
	SenderAddress string
	Rates         []*ExchangeRateInfo
}

func NewExchangeRatesRequestStatus(status byte, senderAddress string, rates []*ExchangeRateInfo) *ExchangeRatesRequestStatus {
	return &ExchangeRatesRequestStatus{Status: status, SenderAddress: senderAddress, Rates: rates}
}

func NewPortalExchangeRates(metaType int, senderAddress string, currency []*ExchangeRateInfo) (*PortalExchangeRates, error) {
	metadataBase := MetadataBase{Type: metaType}

	portalExchangeRates := &PortalExchangeRates{
		SenderAddress: senderAddress,
		Rates:         currency,
	}

	portalExchangeRates.MetadataBase = metadataBase

	return portalExchangeRates, nil
}

type PortalExchangeRatesContent struct {
	SenderAddress   string
	Rates           []*ExchangeRateInfo
	TxReqID         common.Hash
	LockTime        int64
}

func (portalExchangeRates PortalExchangeRates) Hash() *common.Hash {
	record := portalExchangeRates.MetadataBase.Hash().String()
	record += portalExchangeRates.SenderAddress
	for _, rateInfo := range portalExchangeRates.Rates {
		record += rateInfo.PTokenID
		record += strconv.FormatUint(rateInfo.Rate, 10)
	}

	// final hash
	hash := common.HashH([]byte(record))
	return &hash
}

func (portalExchangeRates *PortalExchangeRates) CalculateSize() uint64 {
	return calculateSize(portalExchangeRates)
}
