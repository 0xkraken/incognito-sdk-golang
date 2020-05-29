package transaction

import (
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/rpcclient"
	"testing"
)

func TestCreateAndSendNormalTx(t *testing.T) {
	//rpcClient := rpcclient.NewHttpClient("", "http", "51.83.36.184", 9335)

	rpcClient := rpcclient.NewHttpClient("https://test-node.incognito.org", "https", "test-node.incognito.org", 0)

	privateKeyStr := "112t8rnXBS7jJ4iqFon5rM66ex1Fc7sstNrJA9iMKgNURMUf3rywYfJ4c5Kpxw1BgL1frj9Nu5uL5vpemn9mLUW25CD1w7khX88WdauTVyKa"
	paymentInfoParams := map[string]uint64{
		"12S5pBBRDf1GqfRHouvCV86sWaHzNfvakAWpVMvNnWu2k299xWCgQzLLc9wqPYUHfMYGDprPvQ794dbi6UU1hfRN4tPiU61txWWenhC" : 1 * 1e9,
	}

	txID, err := CreateAndSendNormalTx(rpcClient, privateKeyStr, paymentInfoParams, 10, false)
	if err != nil {
		fmt.Printf("Error when create and send normal tx %v\n", err)
		return
	}

	fmt.Printf("Send tx successfully - TxID %v !!!", txID)
}

func TestCreateAndSendTxRelayHeaderBlock(t *testing.T) {
	rpcClient := rpcclient.NewHttpClient("", "http", "127.0.0.1", 9334 )

	privateKeyStr := "112t8rnjeorQyyy36Vz5cqtfQNoXuM7M2H92eEvLWimiAtnQCSZiP2HXpMW7mECSRXeRrP8yPwxKGuziBvGVfmxhQJSt2KqHAPZvYmM1ZKwR"
	bnbHeaderStr := "eyJoZWFkZXIiOnsidmVyc2lvbiI6eyJibG9jayI6MTAsImFwcCI6MH0sImNoYWluX2lkIjoiQmluYW5jZS1DaGFpbi1OaWxlIiwiaGVpZ2h0Ijo3NDY5NDQ0NSwidGltZSI6IjIwMjAtMDQtMDFUMTA6MTc6MTkuNTg0NjY2NjUzWiIsIm51bV90eHMiOjAsInRvdGFsX3R4cyI6NTA0MDUzMDQsImxhc3RfYmxvY2tfaWQiOnsiaGFzaCI6IjZGNUMzNTQ3MzVDRERBOEY4RTg2RjQ4QjZCRDEzNDUyNTI5Qjk2RTlBQUIwQTY1ODQxNkNBRjZFMTI0MDNDNUMiLCJwYXJ0cyI6eyJ0b3RhbCI6MSwiaGFzaCI6IkU5M0VBRTM4MUY5QkMzNEQyOUYxNkQ4M0YyN0JCMzA3RjM4RUI5MjJGNjM3OTlGMjkzNUIyRjVFNzA2RDA3NTcifX0sImxhc3RfY29tbWl0X2hhc2giOiI0NzcxMDhCMjJBNUQ1NEQ2MkJFNDkyM0M4N0MzNkJENzMxNEZDOUU4QUFCMzc2MTE0MDIxOTAwOTI5RUM1MUQxIiwiZGF0YV9oYXNoIjoiIiwidmFsaWRhdG9yc19oYXNoIjoiODBEOUFCMEZDMTBEMThDQTBFMDgzMkQ1RjRDMDYzQzU0ODlFQzE0NDNERkI3MzgyNTJEMDM4QTgyMTMxQjI3QSIsIm5leHRfdmFsaWRhdG9yc19oYXNoIjoiODBEOUFCMEZDMTBEMThDQTBFMDgzMkQ1RjRDMDYzQzU0ODlFQzE0NDNERkI3MzgyNTJEMDM4QTgyMTMxQjI3QSIsImNvbnNlbnN1c19oYXNoIjoiMjk0RDhGQkQwQjk0Qjc2N0E3RUJBOTg0MEYyOTlBMzU4NkRBN0ZFNkI1REVBRDNCN0VFQ0JBMTkzQzQwMEY5MyIsImFwcF9oYXNoIjoiRDgxM0Q0RTAyQkYzMTM3RjAyNkY3NTM1MkU2N0ZEQ0U1NEMzMUQwRDYyMTYxMDAzQUQ2OUI1OTAwQ0FDMjE2QSIsImxhc3RfcmVzdWx0c19oYXNoIjoiIiwiZXZpZGVuY2VfaGFzaCI6IiIsInByb3Bvc2VyX2FkZHJlc3MiOiJGQzMxMDhEQzM4MTQ4ODhGNDE4NzQ1MjE4MkJDMUJBRjgzQjcxQkM5In0sImRhdGEiOnsidHhzIjpudWxsfSwiZXZpZGVuY2UiOnsiZXZpZGVuY2UiOm51bGx9LCJsYXN0X2NvbW1pdCI6eyJibG9ja19pZCI6eyJoYXNoIjoiNkY1QzM1NDczNUNEREE4RjhFODZGNDhCNkJEMTM0NTI1MjlCOTZFOUFBQjBBNjU4NDE2Q0FGNkUxMjQwM0M1QyIsInBhcnRzIjp7InRvdGFsIjoxLCJoYXNoIjoiRTkzRUFFMzgxRjlCQzM0RDI5RjE2RDgzRjI3QkIzMDdGMzhFQjkyMkY2Mzc5OUYyOTM1QjJGNUU3MDZEMDc1NyJ9fSwicHJlY29tbWl0cyI6W3sidHlwZSI6MiwiaGVpZ2h0Ijo3NDY5NDQ0NCwicm91bmQiOjAsImJsb2NrX2lkIjp7Imhhc2giOiI2RjVDMzU0NzM1Q0REQThGOEU4NkY0OEI2QkQxMzQ1MjUyOUI5NkU5QUFCMEE2NTg0MTZDQUY2RTEyNDAzQzVDIiwicGFydHMiOnsidG90YWwiOjEsImhhc2giOiJFOTNFQUUzODFGOUJDMzREMjlGMTZEODNGMjdCQjMwN0YzOEVCOTIyRjYzNzk5RjI5MzVCMkY1RTcwNkQwNzU3In19LCJ0aW1lc3RhbXAiOiIyMDIwLTA0LTAxVDEwOjE3OjE5LjU4NDMzOTA2OFoiLCJ2YWxpZGF0b3JfYWRkcmVzcyI6IjA2RkQ2MDA3OEVCNEMyMzU2MTM3REQ1MDAzNjU5N0RCMjY3Q0Y2MTYiLCJ2YWxpZGF0b3JfaW5kZXgiOjAsInNpZ25hdHVyZSI6IlFLQitFQ0NCeVl2d3ljREFRaWs3bDJGbDhjRmdVR1paV0tHbVNMZXJEWURpQWgvcS85a0srMC9kYzBRRDhQTjZ4Rm53MWtNYlRDTWNiUXBlTi9pZkFBPT0ifSx7InR5cGUiOjIsImhlaWdodCI6NzQ2OTQ0NDQsInJvdW5kIjowLCJibG9ja19pZCI6eyJoYXNoIjoiNkY1QzM1NDczNUNEREE4RjhFODZGNDhCNkJEMTM0NTI1MjlCOTZFOUFBQjBBNjU4NDE2Q0FGNkUxMjQwM0M1QyIsInBhcnRzIjp7InRvdGFsIjoxLCJoYXNoIjoiRTkzRUFFMzgxRjlCQzM0RDI5RjE2RDgzRjI3QkIzMDdGMzhFQjkyMkY2Mzc5OUYyOTM1QjJGNUU3MDZEMDc1NyJ9fSwidGltZXN0YW1wIjoiMjAyMC0wNC0wMVQxMDoxNzoxOS41NjY4MTE4ODJaIiwidmFsaWRhdG9yX2FkZHJlc3MiOiIxOEU2OUNDNjcyOTczOTkyQkI1Rjc2RDA0OUE1QjJDNURERjc3NDM2IiwidmFsaWRhdG9yX2luZGV4IjoxLCJzaWduYXR1cmUiOiJaUWhraU41YkFwWnZ4MXpxWlBJY1Bxcm9JQ1JzNnM5R0ttb00wZXZKdWR1U0hsT29hSGNSWlUxQmJaTzhoc0N2K0VZREpsL2dmTzY4QXRiN3VQUjBEQT09In0seyJ0eXBlIjoyLCJoZWlnaHQiOjc0Njk0NDQ0LCJyb3VuZCI6MCwiYmxvY2tfaWQiOnsiaGFzaCI6IjZGNUMzNTQ3MzVDRERBOEY4RTg2RjQ4QjZCRDEzNDUyNTI5Qjk2RTlBQUIwQTY1ODQxNkNBRjZFMTI0MDNDNUMiLCJwYXJ0cyI6eyJ0b3RhbCI6MSwiaGFzaCI6IkU5M0VBRTM4MUY5QkMzNEQyOUYxNkQ4M0YyN0JCMzA3RjM4RUI5MjJGNjM3OTlGMjkzNUIyRjVFNzA2RDA3NTcifX0sInRpbWVzdGFtcCI6IjIwMjAtMDQtMDFUMTA6MTc6MTkuNTY1MzkzNzg1WiIsInZhbGlkYXRvcl9hZGRyZXNzIjoiMzQ0QzM5QkI4RjQ1MTJENkNBQjFGNkFBRkFDMTgxMUVGOUQ4QUZERiIsInZhbGlkYXRvcl9pbmRleCI6Miwic2lnbmF0dXJlIjoiSHdtMUNscWpDODdVeUlpNFY4cksrMUg5ZUZWMS9KSTVPZTgwdnVQZktONGNmakJlRmV3RDZxcHNHL3VMcnRDbVFtSFNhcTF1V1g3bHI5eFdUQis5QVE9PSJ9LHsidHlwZSI6MiwiaGVpZ2h0Ijo3NDY5NDQ0NCwicm91bmQiOjAsImJsb2NrX2lkIjp7Imhhc2giOiI2RjVDMzU0NzM1Q0REQThGOEU4NkY0OEI2QkQxMzQ1MjUyOUI5NkU5QUFCMEE2NTg0MTZDQUY2RTEyNDAzQzVDIiwicGFydHMiOnsidG90YWwiOjEsImhhc2giOiJFOTNFQUUzODFGOUJDMzREMjlGMTZEODNGMjdCQjMwN0YzOEVCOTIyRjYzNzk5RjI5MzVCMkY1RTcwNkQwNzU3In19LCJ0aW1lc3RhbXAiOiIyMDIwLTA0LTAxVDEwOjE3OjE5LjU5NDU1MTU1NFoiLCJ2YWxpZGF0b3JfYWRkcmVzcyI6IjM3RUYxOUFGMjk2NzlCMzY4RDJCOUU5REUzRjg3NjlCMzU3ODY2NzYiLCJ2YWxpZGF0b3JfaW5kZXgiOjMsInNpZ25hdHVyZSI6ImxJMkhwRmhITmhRYlptUEJwMkpsQmhFY3NvckYxM3hWYTJuai9CODJKdEdsRGxxU09rMlNaUGpPNHU4L2dQTWpFSVRGcEx0cmtpdXE1bm00dFpyUURRPT0ifSx7InR5cGUiOjIsImhlaWdodCI6NzQ2OTQ0NDQsInJvdW5kIjowLCJibG9ja19pZCI6eyJoYXNoIjoiNkY1QzM1NDczNUNEREE4RjhFODZGNDhCNkJEMTM0NTI1MjlCOTZFOUFBQjBBNjU4NDE2Q0FGNkUxMjQwM0M1QyIsInBhcnRzIjp7InRvdGFsIjoxLCJoYXNoIjoiRTkzRUFFMzgxRjlCQzM0RDI5RjE2RDgzRjI3QkIzMDdGMzhFQjkyMkY2Mzc5OUYyOTM1QjJGNUU3MDZEMDc1NyJ9fSwidGltZXN0YW1wIjoiMjAyMC0wNC0wMVQxMDoxNzoxOS42NDQxOTk2NjlaIiwidmFsaWRhdG9yX2FkZHJlc3MiOiI2MjYzM0Q5REI3RUQ3OEU5NTFGNzk5MTNGREM4MjMxQUE3N0VDMTJCIiwidmFsaWRhdG9yX2luZGV4Ijo0LCJzaWduYXR1cmUiOiJXRUEzUGlrZUhVb28yMzkwNVNBR2d6bFdFeko4UTJ2VEJWcjFYM0UxUjNCd3BpMnd1cFFrZzZvOGRFWUd4YUFYemYzanZheHpwendEd09NTUlIVStDQT09In0seyJ0eXBlIjoyLCJoZWlnaHQiOjc0Njk0NDQ0LCJyb3VuZCI6MCwiYmxvY2tfaWQiOnsiaGFzaCI6IjZGNUMzNTQ3MzVDRERBOEY4RTg2RjQ4QjZCRDEzNDUyNTI5Qjk2RTlBQUIwQTY1ODQxNkNBRjZFMTI0MDNDNUMiLCJwYXJ0cyI6eyJ0b3RhbCI6MSwiaGFzaCI6IkU5M0VBRTM4MUY5QkMzNEQyOUYxNkQ4M0YyN0JCMzA3RjM4RUI5MjJGNjM3OTlGMjkzNUIyRjVFNzA2RDA3NTcifX0sInRpbWVzdGFtcCI6IjIwMjAtMDQtMDFUMTA6MTc6MTkuNjQ4OTg5MTM0WiIsInZhbGlkYXRvcl9hZGRyZXNzIjoiN0IzNDNFMDQxQ0ExMzAwMDBBOEJDMDBDMzUxNTJCRDdFNzc0MDAzNyIsInZhbGlkYXRvcl9pbmRleCI6NSwic2lnbmF0dXJlIjoicXdnaDlTRGlHK3hVc2V6a2JTR3dES05tUEUrSHp6RVZGL3huRUVoNi9HeFpxbGZLcXFxODZLSEVrQTM4VW1xVUZiM3NOaHVtQ1BsRlIwSG9RaHlMQmc9PSJ9LHsidHlwZSI6MiwiaGVpZ2h0Ijo3NDY5NDQ0NCwicm91bmQiOjAsImJsb2NrX2lkIjp7Imhhc2giOiI2RjVDMzU0NzM1Q0REQThGOEU4NkY0OEI2QkQxMzQ1MjUyOUI5NkU5QUFCMEE2NTg0MTZDQUY2RTEyNDAzQzVDIiwicGFydHMiOnsidG90YWwiOjEsImhhc2giOiJFOTNFQUUzODFGOUJDMzREMjlGMTZEODNGMjdCQjMwN0YzOEVCOTIyRjYzNzk5RjI5MzVCMkY1RTcwNkQwNzU3In19LCJ0aW1lc3RhbXAiOiIyMDIwLTA0LTAxVDEwOjE3OjE5LjU2ODMwODE3MVoiLCJ2YWxpZGF0b3JfYWRkcmVzcyI6IjkxODQ0RDI5NkJEOEU1OTE0NDhFRkM2NUZENkFENTFBODg4RDU4RkEiLCJ2YWxpZGF0b3JfaW5kZXgiOjYsInNpZ25hdHVyZSI6Ilh2QXZlZTZlT3ZacEZZZDNGdXptN1hPSUZucDVyaHNwNDdweWZIQVVjNkc4SG5WZHpRYVdsd0ZrM3IzRWltbEtRcjNubE9qVVZhem54Z0duMk9IRkJ3PT0ifSx7InR5cGUiOjIsImhlaWdodCI6NzQ2OTQ0NDQsInJvdW5kIjowLCJibG9ja19pZCI6eyJoYXNoIjoiNkY1QzM1NDczNUNEREE4RjhFODZGNDhCNkJEMTM0NTI1MjlCOTZFOUFBQjBBNjU4NDE2Q0FGNkUxMjQwM0M1QyIsInBhcnRzIjp7InRvdGFsIjoxLCJoYXNoIjoiRTkzRUFFMzgxRjlCQzM0RDI5RjE2RDgzRjI3QkIzMDdGMzhFQjkyMkY2Mzc5OUYyOTM1QjJGNUU3MDZEMDc1NyJ9fSwidGltZXN0YW1wIjoiMjAyMC0wNC0wMVQxMDoxNzoxOS41NjcxNDUwNjFaIiwidmFsaWRhdG9yX2FkZHJlc3MiOiJCMzcyNzE3MkNFNjQ3M0JDNzgwMjk4QTJENjZDMTJGMUExNEY1QjJBIiwidmFsaWRhdG9yX2luZGV4Ijo3LCJzaWduYXR1cmUiOiJEVlZRajVpblhZM2JxZEtBNG1KL3FpZVZpclpOY1FyMjVtZWgyeU5yaldqS1pjWUpUQ0VLdVh3cHBzTHBGcDRBSHJYOGh4WXUvZmJFVVZPTlpaRmFBQT09In0seyJ0eXBlIjoyLCJoZWlnaHQiOjc0Njk0NDQ0LCJyb3VuZCI6MCwiYmxvY2tfaWQiOnsiaGFzaCI6IjZGNUMzNTQ3MzVDRERBOEY4RTg2RjQ4QjZCRDEzNDUyNTI5Qjk2RTlBQUIwQTY1ODQxNkNBRjZFMTI0MDNDNUMiLCJwYXJ0cyI6eyJ0b3RhbCI6MSwiaGFzaCI6IkU5M0VBRTM4MUY5QkMzNEQyOUYxNkQ4M0YyN0JCMzA3RjM4RUI5MjJGNjM3OTlGMjkzNUIyRjVFNzA2RDA3NTcifX0sInRpbWVzdGFtcCI6IjIwMjAtMDQtMDFUMTA6MTc6MTkuNTg0NjY2NjUzWiIsInZhbGlkYXRvcl9hZGRyZXNzIjoiQjZGMjBDN0ZBQTJCMkY2RjI0NTE4RkEwMkI3MUNCNUY0QTA5RkJBMyIsInZhbGlkYXRvcl9pbmRleCI6OCwic2lnbmF0dXJlIjoiYS9KanV3U0w2Y0pqR1dGQnVCa2xDcGNpbDI3eW9ZVzJJbW5EVTF5QUtwSzVaenZST083QlQyNlhIUnVzcWYydFJTWkxyUEc0alJkZ3VsYkxtQjlIQXc9PSJ9LHsidHlwZSI6MiwiaGVpZ2h0Ijo3NDY5NDQ0NCwicm91bmQiOjAsImJsb2NrX2lkIjp7Imhhc2giOiI2RjVDMzU0NzM1Q0REQThGOEU4NkY0OEI2QkQxMzQ1MjUyOUI5NkU5QUFCMEE2NTg0MTZDQUY2RTEyNDAzQzVDIiwicGFydHMiOnsidG90YWwiOjEsImhhc2giOiJFOTNFQUUzODFGOUJDMzREMjlGMTZEODNGMjdCQjMwN0YzOEVCOTIyRjYzNzk5RjI5MzVCMkY1RTcwNkQwNzU3In19LCJ0aW1lc3RhbXAiOiIyMDIwLTA0LTAxVDEwOjE3OjE5LjY0NTE4ODQyN1oiLCJ2YWxpZGF0b3JfYWRkcmVzcyI6IkUwREQ3MjYwOUNDMTA2MjEwRDFBQTEzOTM2Q0I2N0I5M0EwQUVFMjEiLCJ2YWxpZGF0b3JfaW5kZXgiOjksInNpZ25hdHVyZSI6Ild2ZGYxbFhIVWpBSkVrWE55dlgvZ3dEQXl4ODUwbW9xZXorS0M0UkJ6QXZFQWNDQ1pJTzBKYXF6SDNqRzVkelhuNVVlU1pXbFJGdE9SRGpZSVFhNEJRPT0ifSx7InR5cGUiOjIsImhlaWdodCI6NzQ2OTQ0NDQsInJvdW5kIjowLCJibG9ja19pZCI6eyJoYXNoIjoiNkY1QzM1NDczNUNEREE4RjhFODZGNDhCNkJEMTM0NTI1MjlCOTZFOUFBQjBBNjU4NDE2Q0FGNkUxMjQwM0M1QyIsInBhcnRzIjp7InRvdGFsIjoxLCJoYXNoIjoiRTkzRUFFMzgxRjlCQzM0RDI5RjE2RDgzRjI3QkIzMDdGMzhFQjkyMkY2Mzc5OUYyOTM1QjJGNUU3MDZEMDc1NyJ9fSwidGltZXN0YW1wIjoiMjAyMC0wNC0wMVQxMDoxNzoxOS42NDUyNTMzOTVaIiwidmFsaWRhdG9yX2FkZHJlc3MiOiJGQzMxMDhEQzM4MTQ4ODhGNDE4NzQ1MjE4MkJDMUJBRjgzQjcxQkM5IiwidmFsaWRhdG9yX2luZGV4IjoxMCwic2lnbmF0dXJlIjoidllrMUI5SDcyakFKSTlvaThiZEI3QzBHS05OM2h1N2FUV3dXVG5EVjdPbkpaS0M0SHl5SDJoSytxZG9USnE2ZE03U2s2aDlxcllTclltc1JZTDRSQmc9PSJ9XX19"
	bnbBlockHeight := int64(74694445)

	txID, err := CreateAndSendTxRelayBNBHeader(rpcClient, privateKeyStr, bnbHeaderStr, bnbBlockHeight, 20)
	if err != nil {
		fmt.Printf("Error when create and send tx relay bnb block %v\n", err)
		return
	}

	fmt.Printf("Send tx successfully - TxID %v !!!", txID)
}

func TestCreateAndSendTxPortalExchangeRate(t *testing.T) {
	rpcClient := rpcclient.NewHttpClient("", "http", "127.0.0.1", 9334)

	privateKeyStr := "112t8rnjeorQyyy36Vz5cqtfQNoXuM7M2H92eEvLWimiAtnQCSZiP2HXpMW7mECSRXeRrP8yPwxKGuziBvGVfmxhQJSt2KqHAPZvYmM1ZKwR"
	exchangeRateParam := map[string]uint64{
		"b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696": 8000000000,
		"b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b": 40000000,
		"0000000000000000000000000000000000000000000000000000000000000004": 500000,
	}

	txID, err := CreateAndSendTxPortalExchangeRate(rpcClient, privateKeyStr, exchangeRateParam, 10)
	if err != nil {
		fmt.Printf("Error when create and send tx relay bnb block %v\n", err)
		return
	}

	fmt.Printf("Send tx successfully - TxID %v !!!", txID)
}

func TestGetBalancePRV(t *testing.T) {
	rpcClient := rpcclient.NewHttpClient("", "http", "127.0.0.1", 9334)
	privateKeyStr := "112t8rnjeorQyyy36Vz5cqtfQNoXuM7M2H92eEvLWimiAtnQCSZiP2HXpMW7mECSRXeRrP8yPwxKGuziBvGVfmxhQJSt2KqHAPZvYmM1ZKwR"

	balance, err := GetBalancePRV(rpcClient, privateKeyStr)
	if err != nil {
		fmt.Printf("Error when get balance %v\n", err)
		return
	}

	fmt.Printf("Balance %v", balance)
}

func TestSplitUTXOs(t *testing.T) {
	rpcClient := rpcclient.NewHttpClient("", "http", "127.0.0.1", 9334)
	privateKeyStr := "112t8rnjeorQyyy36Vz5cqtfQNoXuM7M2H92eEvLWimiAtnQCSZiP2HXpMW7mECSRXeRrP8yPwxKGuziBvGVfmxhQJSt2KqHAPZvYmM1ZKwR"

	err := SplitUTXOs(rpcClient, privateKeyStr, 300, 10)
	if err != nil {
		fmt.Printf("ERR: %v\n", err)
	}
}
