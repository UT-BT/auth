package errors

var errorMessages = map[string]string{
	"auth_storage_failed":   "Failed to store authentication data.",
	"no_auth_data":          "No authentication data was received.",
	"unknown":               "An unexpected error occurred.",
	"invalid_hwid":          "Invalid HWID. Please use the Login button from your UT instance and try again.",
	"internal_server_error": "An internal server error occurred. Please try again later.",
}

func GetErrorMessage(code string) string {
	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	return errorMessages["unknown"]
}
