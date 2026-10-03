#!/bin/sh
# Container health (docs/docker.md): the agent answers on its control
# socket; a signer container is healthy while its socket exists.
set -eu
role=$(cat /run/webjet-role 2>/dev/null || echo agent)
case "$role" in
    agent)
        webjetctl --json status > /dev/null
        ;;
    signer)
        [ -S "${WEBJET_SIGNER_SOCKET:-/run/webjet/signer.sock}" ]
        ;;
    *)
        exit 0
        ;;
esac
