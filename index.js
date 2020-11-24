/* eslint camelcase: 0 */
const EventEmitter = require('events')

const lpstream = require('length-prefixed-stream')

const {
  crypto_sign_BYTES,
  crypto_generichash_BYTES,

  crypto_sign_detached,
  crypto_sign_verify_detached,
  crypto_generichash

} = require('sodium-universal')

const { AbstractFlood } = require('abstract-flood')

const { Message } = require('./messages')

const NONCE_INDEX_BYTES = 4

class P2PlexGossip extends EventEmitter {
  static async create (opts) {
    const gossip = new P2PlexGossip(opts)

    await gossip.init()

    return gossip
  }

  constructor ({
    swarm,
    peers,
    id,
    nonce = Buffer.from([]),

    ttl,
    lruSize,
    messageIndex,

    keyPair,

    sign = (message) => defaultSign(this.keyPair, message),
    verify = (id, message, signature) => defaultVerify(this.peers, id, message, signature),
    hashBytes = defaultHashBytes
  }) {
    super()
    this.peers = peers
    this.swarm = swarm
    this.nonce = nonce
    this.keyPair = keyPair
    this.nonceIndex = 0
    this.id = id || keyPair.publicKey

    this.connections = new Set()
    this.channel = null

    const floodOpts = {
      id: this.id
    }
    if (ttl) floodOpts.ttl = ttl
    if (lruSize) floodOpts.lruSize = lruSize
    if (messageIndex) floodOpts.messageIndex = messageIndex

    this.flood = new AbstractFlood(floodOpts)

    this._sign = sign
    this._verify = verify
    this._hashBytes = hashBytes
  }

  get id () {
    return this.swarm.publicKey
  }

  async init () {
    this.flood.on('message', async (message) => {
      try {
        await this._handleMessage(message)
      } catch (e) {
        this.emit('error', e)
      }
    })

    this.flood.on('broadcast', (message) => {
      for (const stream of this.connections) {
        stream.write(message)
      }
    })

    this._onConnection = (peer) => this._handleConnection(peer)

    this.swarm.on('connection', this._onConnection)

    this.channel = await this.generateChannel()

    this.swarm.join(this.channel, { announce: true, lookup: true })

    await EventEmitter.once(this, 'connection')
  }

  async generateChannel () {
    const peerKeys = [...this.peers.keys()].map((key) => Buffer.from(key, 'hex'))
    const bytes = Buffer.concat([this.nonce, ...peerKeys])

    return this._hashBytes(bytes)
  }

  async sign (data) {
    const indexNonce = Buffer.alloc(NONCE_INDEX_BYTES)
    indexNonce.writeInt32BE(this.nonceIndex++)
    const nonce = Buffer.concat([indexNonce, this.nonce])
    const toSign = Buffer.concat([data, nonce])

    const signature = await this._sign(toSign)
    const from = this.id

    return { from, signature, nonce, data }
  }

  async verify (from, data, nonce, signature) {
    const isValidNonce = this.isValidNonce(nonce)

    if (!isValidNonce) return false

    const toSign = Buffer.concat([data, nonce])
    return this._verify(from, toSign, signature)
  }

  async _handleMessage (message) {
    const { from, nonce, signature, data } = Message.decode(message)
    const isValid = await this.verify(from, data, nonce, signature)

    if (isValid) {
      this.emit('message', data, from, nonce, signature)
    } else {
      this.emit('error-invalid', data, from, nonce, signature)
    }
  }

  async _handleFromPeer (data) {
    this.flood.handleMessage(data)
  }

  async _handleConnection (peer) {
    const peerKey = peer.publicKey.toString('hex')
    const isPeer = this.peers.has(peerKey)
    if (!isPeer) return
    const stream = peer.createSharedStream(this.channel)

    const encode = lpstream.encode()
    const decode = lpstream.decode()

    decode.on('data', (data) => this._handleFromPeer(data))

    this.connections.add(encode)

    stream.once('end', () => {
      this.connections.delete(encode)
    })

    stream.pipe(decode)
    encode.pipe(stream)

    this.emit('connection', peer, stream)
  }

  isValidNonce (nonce) {
    return nonce.slice(NONCE_INDEX_BYTES).equals(this.nonce)
  }

  async broadcast (data) {
    const { signature, nonce, from } = await this.sign(data)
    this.flood.broadcast(Message.encode({
      from,
      nonce,
      signature,
      data
    }))
  }
}

module.exports = P2PlexGossip

function defaultSign (keyPair, message) {
  const signature = Buffer.alloc(crypto_sign_BYTES)

  crypto_sign_detached(signature, message, keyPair.secretKey)

  return signature
}

function defaultVerify (peers, id, message, signature) {
  const publicKey = peers.get(id.toString('hex'))

  return crypto_sign_verify_detached(signature, message, publicKey)
}
function defaultHashBytes (bytes) {
  const hash = Buffer.alloc(crypto_generichash_BYTES)

  crypto_generichash(hash, bytes)

  return hash
}
