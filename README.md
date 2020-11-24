# p2plex-gossip
Create a secure (ish) swarm of peers to gossip over P2Plex

**Work in progress**

## How it works

- Get a p2plex instance
- Get a set of peers you wish to gossip with
- Set of peers should contain their p2plex public keys as well as their public keys used for signing messages
- Generate a key to find peers based on the set
- Optionally provide a nonce to mix into the key and into messages (useful to avoid replay attacks)
- Find peers for the key
- Find connections from peers and open streams for the key for them
- Use abstract-gossip to send and recieve messages from peers

## API

```JavaScript
const Gossip = require('p2plex-gossip')

const swarm = p2plex()

const peers = new Map()

peers.set(remotePublicKey.toString('hex'), signingPublicKey)

const gossip = await Gossip.create({
	// P2Plex instance to use, the public key will be used for swarming
	swarm,

	// List of peers to gossip with
	// Map of `remotePublicKey` to `signingPublicKey`
	peers,

	// Your ID in the list
	// If not provided `keyPair.publicKey` will be used
	id,

	// Pass a nonce to prevent replay attacks
	// Must be a buffer with unique bytes
	nonce,

	// Keypair used for signing
	// Should be compatible with [libsodium_crypto_sign_*](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
	keyPair,

	// Alternately you can specify custom signing and verifying functions
	// Sign a message for your ID
	async sign(message) { return signature},
	// Given a peer's publicKey, a message and a signature, verify that it's valid
	// The `id` will be the value part of the pair inside the `peers` map
	async verify(id, message, signature) { return isValid},
	// Pass a custom hash function for generating keys
	async hashBytes(bytes) { return hash}
})

// Listen on messages being gossiped in the swarm
gossip.on('message', (data, from) => {
	// Saw a message that got broadcasted by `from`
	// This was cryptographically verified to come from them
	// Data is the data that the original peer sent out
})

// Broadcast some data to the swarm
// `data` must be a Buffer
// Signed with nonce to avoid replay attacks
gossip.broadcast(data)

// Sign some data to send out
const signedData = await gossip.sign(data)
const {from, signature, nonce, data} = signedData

// Verify that some data you got was signed
// The `from` ID is the remotePublic key of the peer
const isValid = await gossip.verify(from, data, nonce, signature)
```
