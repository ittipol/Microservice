package main

type services struct {
	Name        string
	Enable      bool
	RoutePrefix string
	URL         string
}

// type auth struct {
// 	except []except
// }

type configuration struct {
	Services []services
	// Auth
}

var Config *configuration
