# bitcoin-rs

A Bitcoin client written in Rust without std.

The goal of this client is to be able to run a light client in a zkVM like
[o1vm](https://github.com/o1-labs/proof-systems/tree/master/o1vm) to provide a
bridge from Bitcoin to Mina, and provide value settlements between the two
chains.

This client uses the reference implementation using
[this commit](https://github.com/bitcoin/bitcoin/tree/cac846c2fbf6fc69bfc288fd387aa3f68d84d584).


## Tweets

Source: https://x.com/dwillems42/status/1864023579400274327

> I can explain further how it could be implemented, if someone wants to take
> over. Note that it is only an idea to make bridge from Bitcoin to Mina, i.e.
> verifying the Bitcoin chain on Mina. It could for instance be used as “verified
> checkpoints” when we want to synchronize the chain (note that it could be
> generalized to any other chains), and some companies could provide this as a
> service (please, DM me if you want to achieve this — I do have other ideas, but
> no time right now). Also, it is not something I commit to do. There might also
> be some details I did not think about.
> I do not know how the bridge from Mina to Bitcoin could be done. Checking the
> work on BitVM(2) from Liam and others could be a good starting point, and might
> be way smarter/easier than what I could propose. I guess some cryptographic
> primitives must be added/changed.
>
> Start with https://github.com/dannywillems/bitcoin-rs. Mostly, a Bitcoin VM must
> be implemented. Initially, I wanted to make a light client, but it seems there
> could be something easier. Note that this idea is not new, and I do think people
> implemented it with folding (spoiler — that's what I would like to achieve with
> Arrabiata, see o1-labs/proof-systems).
> Verifying a Bitcoin transaction is simply executing a script written using
> Bitcoin opcodes, that can be run in a Bitcoin VM.
>
> You can start by taking a look at all the opcodes, located
> [here](https://github.com/dannywillems/bitcoin-rs/blob/main/src/script.rs#L36).
> All opcodes can be seen as an individual custom gate, and what you would need to
> implement is the corresponding circuit for each instruction, like OP_HASH160
> [here](https://github.com/dannywillems/bitcoin-rs/blob/main/src/script.rs#L992).
> And a script is simply a composition of each circuit that can be composed using
> Halo2 or Pickles/Kimchi. The easiest way to do this to have a verified
> checkpoint for Bitcoin on Mina is to implement it using Kimchi, and use Pickles
> (the "Halo" variant used by Mina) to perform recursion.
> Some values must be passed as public inputs, like the transaction, the block,
> etc., because it has to be used in the Bitcoin script, like by the opcode
> OP_CHECKSIG.
>
> When we do have a proof for a block, we can hope that it takes less than 10
> minutes, so we can process this for each block at the same rate as the bitcoin
> chain. Not sure if it is the case.
>
> Bitcoin could have a succinct representation this way if you do not care about
> the past. Note also that is roughly the same idea as Mina: you implement a
> "transaction" SNARK and a "blockchain" SNARK. On Mina, you do have more complex
> smart contracts.
>
> I wish to see this on other chains too, like @zcash or @monero , if possible.
> But I do not have enough knowledge, for now.
