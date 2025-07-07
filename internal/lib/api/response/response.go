package response

type Error struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

type ErrorData struct {
	Error Error `json:"error"`
}

func ErrorMsg(code int, msg string) ErrorData {
	return ErrorData{
		Error: Error{
			Code: code,
			Text: msg,
		},
	}
}
