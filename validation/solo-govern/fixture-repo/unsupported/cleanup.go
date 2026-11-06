package main

import (
	"net/http"
	"os"
	"strings"
)

func Wipe(p string) error { return os.RemoveAll(p) }

func Hook(u string) { http.Post(u, "application/json", strings.NewReader("{}")) }
