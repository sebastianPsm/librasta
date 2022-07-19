# OPAQUE support

Optionally, this library supports a possible extension of the RaSTA protocol that performs the *OPAQUE* augmented Password-Authenticated Key Exchange between client and server, and derives a session key that is used as key for the safety code.
To this end, three new protocol PDUs were added: Key Exchange Request, Response, and Client Authentication. They convey the corresponding OPAQUE messages as specified in the [IRTF OPAQUE draft](https://github.com/cfrg/draft-irtf-cfrg-opaque).
We use [libopaque](https://github.com/stef/libopaque) as implementation of OPAQUE.

## Prerequisites
Compiling librasta with OPAQUE support requires the *libsodium* run-time libraries and headers. For example, on Debian/Ubuntu, the package *libsodium-dev* is required.

## How to enable
In order to enable the support, use the `ENABLE_RASTA_OPAQUE` cmake parameter.
After that, you can use the OPAQUE-related configuration options.
See *examples/config/rasta_[client1|server]_kex.cfg* configuration examples for documentation of the options.
In a nutshell, you have configure a Pre-Shared Key in the client and optionally in the server. Alternatively, in the server, you can also specify a blinded version of the password (the password cannot be derived from the server's configuration file in that case), which can be generated using the *record_generator* binary compiled with the examples.
Also, you can specify a rekeying interval - in that interval, client and server will exchange a new session key. If it is not given, a session key is only exchanged at the beginning of the connection.
The server will also teardown the connection if no rekeying occurs during the interval in order to protect from brute-force MITM attacks on the session key.

## How to test
The *example_local_kex* binary will start a server and connect a client to the server.
Use the *examples/example_scripts/example_kex.sh* script to test whether the connection succeeds.
You can disable rekeying by specifiying a second command-line parameter to each binary.