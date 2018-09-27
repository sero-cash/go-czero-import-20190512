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


### Usage

Conversion is done on one or more sets of files. They are all embedded in a new
Go source file, along with a table of contents and an `Asset` function,
which allows quick access to the asset, based on its name.

The simplest invocation generates a `bindata.go` file in the current
working directory. It includes all assets from the `data` directory.

	$ go-bindata data/

To include all input sub-directories recursively, use the elipsis postfix
as defined for Go import paths. Otherwise it will only consider assets in the
input directory itself.

	$ go-bindata data/...

To specify the name of the output file being generated, we use the following:

	$ go-bindata -o myfile.go data/

Multiple input directories can be specified if necessary.

	$ go-bindata dir1/... /path/to/dir2/... dir3


The following paragraphs detail some of the command line options which can be 
supplied to `go-bindata`. Refer to the `testdata/out` directory for various
output examples from the assets in `testdata/in`. Each example uses different
command line options.

To ignore files, pass in regexes using -ignore, for example:

    $ go-bindata -ignore=\\.gitignore data/...

### Accessing an asset

To access asset data, we use the `Asset(string) ([]byte, error)` function which
is included in the generated output.

	data, err := Asset("pub/style/foo.css")
	if err != nil {
		// Asset was not found.
	}

	// use asset data


### Debug vs Release builds

When invoking the program with the `-debug` flag, the generated code does
not actually include the asset data. Instead, it generates function stubs
which load the data from the original file on disk. The asset API remains
identical between debug and release builds, so your code will not have to
change.

This is useful during development when you expect the assets to change often.
The host application using these assets uses the same API in both cases and
will not have to care where the actual data comes from.

An example is a Go webserver with some embedded, static web content like
HTML, JS and CSS files. While developing it, you do not want to rebuild the
whole server and restart it every time you make a change to a bit of
javascript. You just want to build and launch the server once. Then just press
refresh in the browser to see those changes. Embedding the assets with the
`debug` flag allows you to do just that. When you are finished developing and
ready for deployment, just re-invoke `go-bindata` without the `-debug` flag.
It will now embed the latest version of the assets.
