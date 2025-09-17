#!/bin/bash

# -d single domain test
DOMAIN="google.com"
PROTOCOL_UDP="udp"

echo "=== Running single domain: $DOMAIN with protocol $PROTOCOL_UDP ==="
for VERSION in 0,4,6 ; do
    echo ">>> Testing IP version: $VERSION"
    for MOD in {2..10}; do
        echo "Running mod=$MOD ..."
        go run main.go -d "$DOMAIN" -mod "$MOD" -proto "$PROTOCOL_UDP" -v "$VERSION"
        echo "Finished mod=$MOD"
        echo "-----------------------------"
    done
done

# -d domain list test
DOMAIN_LIST_FILE="domainlist.txt"
PROTOCOL_TCP="tcp"

echo "=== Running domain list: $DOMAIN_LIST_FILE with protocol $PROTOCOL_TCP ==="
for VERSION in 0 4 6; do
    echo ">>> Testing IP version: $VERSION"
    for MOD in {2..10}; do
        echo "Running mod=$MOD ..."
        go run main.go -l "$DOMAIN_LIST_FILE" -mod "$MOD" -proto "$PROTOCOL_TCP" -v "$VERSION"
        echo "Finished mod=$MOD"
        echo "-----------------------------"
    done
done

echo "All tasks finished."