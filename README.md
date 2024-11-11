hyper-evite
===========

Create and verifiy topic invites that are timesensitive. Mostly for hyperswarm applications.

Example usage
===

```
import crypto from 'hypercore-crypto'
import Hyperswarm from 'hyperswarm'
import { createInvite, verifyInviteBuffer } from 'hyper-evite'

const keyPair = crypto.keyPair() // used to create and sign the new topic

// create an invite for a new topic!
const { invite, parts } = createInvite(keyPair.secretKey)
console.log(invite)
// prints out a base32 topic string, eg:
// j3rsz834cs7qorc84eupm4x5ce4911tettjc4mbyg8dxeo9tfxhdnp3ugr3ukqjogyaurpb3wqakxp455xgrks18csk6mpjo71ytq8azm16ra1bc9kng6j9fxc4a83penjx7r3tybf33wzp5rexciigeriyszy9331hzgm6nq498hdo 
// this is what you share with others. It is valid for 24 hours

// lets connect on the invite topic
const swarm1 = new Hyperswarm()
const verifyPeer = (req) => {
  if (!verifyInviteBuffer(keyPair.publicKey, req)) return // the invite is bad 
  // let them in!
}

swarm1.on('connection', (conn, peerInfo) => {
  if (!peerInfo.topics.includes(parts.topic)) 
  const rpc = new ProtomuxRPC(conn)
  const rpc.respond('addMe', verifyPeer) 
})
const discovery = swarm1.join(parts.topic, { server: true, client: false })
await discovery.flushed()
```
