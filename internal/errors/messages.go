package errors

var errorMessages = map[string]string{
	"auth_storage_failed": "Failed to store authentication data.",
	"no_auth_data":        "No authentication data was received.",
	"unknown":             "An unexpected error occurred.",
}

func GetErrorMessage(code string) string {
	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	return errorMessages["unknown"]
}
