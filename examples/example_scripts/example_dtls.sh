#!/bin/sh
# needs to be run from top-level directory, i.e. ./examples/example_scripts/example_kex.sh
cd build/examples || exit 1

# let server generate certificates
strace ../dtls_example_local r &
SERVER_INITIAL_PID=$!

sleep 5
kill $SERVER_INITIAL_PID

strace ../dtls_example_local s1 > client.log 2>&1 &
CLIENT_PID=$!

strace ../dtls_example_local r > server.log 2>&1
SERVER_EXIT_CODE=$?

# give client chance to terminate
sleep 5

kill -9 $CLIENT_PID 2>/dev/null

echo "---- Client Log ----"
cat client.log
echo "---- Server Log ----"
cat server.log

rm server.log client.log 2>/dev/null

exit $SERVER_EXIT_CODE
