# Warning

**this repository is related with zcash module, implemented by c++.**

## zcash origin

Zcash is a cryptocurrency aimed at using cryptography to provide enhanced
privacy for its users compared to other cryptocurrencies such as Bitcoin. 
**czero** is the module which is to generate the functionality to make user
transaction address encrypt which provide strongest protection of user's 
privacy.



What are zk-SNARKs?
Zcash is the first widespread application of zk-SNARKs, a novel form of zero-knowledge 
cryptography. The strong privacy guarantee of Zcash is derived from the fact that 
shielded transactions in Zcash can be fully encrypted on the blockchain, yet still be 
verified as valid under the network’s consensus rules by using zk-SNARK proofs.

The acronym zk-SNARK stands for “Zero-Knowledge Succinct Non-Interactive Argument of 
Knowledge,” and refers to a proof construction where one can prove possession of certain 
information, e.g. a secret key, without revealing that information, and without any 
interaction between the prover and verifier.

“Zero-knowledge” proofs allow one party (the prover) to prove to another (the verifier) 
that a statement is true, without revealing any information beyond the validity of the 
statement itself. For example, given the hash of a random number, the prover could convince 
the verifier that there indeed exists a number with this hash value, without revealing 
what it is.

In a zero-knowledge "Proof of Knowledge" the prover can convince the verifier not only 
that the number exists, but that they in fact know such a number - again, without revealing
any information about the number. The difference between "Proof" and "Argument" is quite 
technical and we don't get into it here.

“Succinct” zero-knowledge proofs can be verified within a few milliseconds, with a proof 
length of only a few hundred bytes even for statements about programs that are very large. 
In the first zero-knowledge protocols, the prover and verifier had to communicate back and 
forth for multiple rounds, but in “non-interactive” constructions, the proof consists of a
single message sent from prover to verifier. Currently, the only known way to produce 
zero-knowledge proofs that are non-interactive and short enough to publish to a block chain is
to have an initial setup phase that generates a common reference string shared between 
prover and verifier. We refer to this common reference string as the public parameters 
of the system.

### Installation

To install the library and command line program, use the following:

	go get -u github.com/sero-cash/go-czero-import


