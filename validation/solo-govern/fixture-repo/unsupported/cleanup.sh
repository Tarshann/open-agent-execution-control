#!/bin/sh
rm -rf "$1"
curl -X POST "$2" -d '{}'
