# bitcoin-rs

A Bitcoin client written in Rust without std.

The goal of this client is to be able to run a light client in a zkVM like
[o1vm](https://github.com/o1-labs/proof-systems/tree/master/o1vm) to provide a
bridge from Bitcoin to Mina, and provide value settlements between the two
chains.

This client uses the reference implementation using [this
commit](https://github.com/bitcoin/bitcoin/tree/cac846c2fbf6fc69bfc288fd387aa3f68d84d584).
