#! /bin/bash

# needs to be run from top-level directory, i.e. ./examples/example_scripts/example_local.sh
cd build/examples || exit 1

function run_example_local() {
    MODE=$1

    # Set up fifo to be able to pass in commands
    rm -f /tmp/$MODE-input
    mkfifo /tmp/$MODE-input
    # Keep the fifo open
    cat > /tmp/$MODE-input &

    tail -f /tmp/$MODE-input | ../rasta_example_udp $MODE &
}

run_example_local r
SERVER_PID=$!

# Listen
echo "" > /tmp/r-input
sleep 1


echo "Connecting to server..."

run_example_local s1
CLIENT_PID=$!

# Connect
echo "" > /tmp/s1-input
sleep 5

# Disconnect
echo "" > /tmp/s1-input
wait $CLIENT_PID || break
sleep 1

# Terminate
echo "" > /tmp/r-input
sleep 1


wait $CLIENT_PID && wait $SERVER_PID && exit 0
exit 1
