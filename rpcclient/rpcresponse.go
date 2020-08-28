package rpcclient

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	StackTrace string `json:"stack_trace"`
}

type RPCBaseRes struct {
	Id       int       `json:"id"`
	RPCError *RPCError    `json:"error"`
}

type IncognitoRPCRes struct {
	RPCBaseRes
	Result interface{}
}

type ListOutputCoinsRes struct {
	RPCBaseRes
	Result *ListOutputCoins
}

type HasSerialNumberRes struct {
	RPCBaseRes
	Result []bool
}

type HasSNDerivatorRes struct {
	RPCBaseRes
	Result []bool
}

type SendRawTxRes struct {
	RPCBaseRes
	Result *CreateTransactionResult
}

type GetTxByHashRes struct {
	RPCBaseRes
	Result *TransactionDetail
}