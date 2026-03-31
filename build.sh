#!/bin/bash

mkdir -p dist

if [ ! -f "main.go" ]; then
	echo "main.go not found."
	exit 1
fi

for os in linux darwin; do
	if [ "$os" = "win32" ]; then
		goos="windows"
	else
		goos=$os
	fi
	for arch in x64 arm64; do
		if [ "$arch" = "x64" ]; then
			goarch="amd64"
		else
			goarch=$arch
		fi
		GOOS=$goos GOARCH=$goarch go build -o ./dist/${os}-${arch}/mrrowisp main.go
	done
done

echo "Finished building. Binaries in ./dist/PLATFORM-ARCH/mrrowisp"