#!/bin/sh
if [ -n "$FLAG" ]; then
	echo $FLAG > flag.txt
fi
setarch x86_64 -R ./server
