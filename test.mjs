import test from 'brittle'
import crypto from 'hypercore-crypto'
import { createInvite, verifyInvite, encodeInviteParts } from './index.mjs'

const keypair = crypto.keyPair()

test('invite and verify happy path', async (t) => {
  const now = Date.now()
  const { invite } = createInvite(keypair.secretKey, { now })
  const results = verifyInvite(keypair.publicKey, invite, { now })
  validateAllKeys(results, t)
  t.end()
})

test('expired invite', async (t) => {
  const now = Date.now()
  const { invite } = createInvite(keypair.secretKey, { now })
  const threeDays = now + 3 * 24 * 60 * 60 * 1000
  const results = verifyInvite(keypair.publicKey, invite, { now: threeDays })
  t.absent(results.malformed, 'key: malformed is falsey')
  t.absent(results.signedFailed, 'key: signedFailed is falsey')
  t.ok(results.expired, 'expected expired result')
  t.end()
})

test('bad invite on topic', async (t) => {
  const now = Date.now()
  const { parts } = createInvite(keypair.secretKey, { now })
  // randomly switch a part of the topic string
  mutateBufferAt(parts.topic, 2)
  const badInvite = encodeInviteParts(parts)
  const results = verifyInvite(keypair.publicKey, badInvite, { now })
  t.absent(results.malformed, 'key: malformed is falsey')
  t.ok(results.signedFailed, 'expected signed failed result')
  t.end()
})

test('bad signature', async (t) => {
  const now = Date.now()
  const { parts } = createInvite(keypair.secretKey, { now })
  // randomly switch a part of the topic string
  mutateBufferAt(parts.signature, 2)
  const badInvite = encodeInviteParts(parts)
  const results = verifyInvite(keypair.publicKey, badInvite, { now })
  t.absent(results.malformed, 'key: malformed is falsey')
  t.ok(results.signedFailed, 'expected signed failed result')
  t.end()
})

test('modified timestamp', async (t) => {
  const now = Date.now()
  const { parts } = createInvite(keypair.secretKey, { now })
  // randomly switch a part of the topic string
  mutateBufferAt(parts.expirationBuffer, 2)
  const badInvite = encodeInviteParts(parts)
  const results = verifyInvite(keypair.publicKey, badInvite, { now })
  t.absent(results.malformed, 'key: malformed is falsey')
  t.ok(results.signedFailed, 'expected signed failed result')
  t.end()
})

function validateAllKeys (results, t) {
  const keys = Object.keys(results)
  for (const key of keys) {
    if (results[key]) t.fail(`key: ${key} failed`)
    else t.pass(`key: ${key} false`)
  }
}

function mutateBufferAt (buffer, index) {
  if (index < 0 || index >= buffer.length) {
    throw new RangeError('Index out of bounds')
  }

  // Generate a random byte that's different from the current one
  let newByte
  do {
    newByte = Math.floor(Math.random() * 256) // Random byte value from 0 to 255
  } while (newByte === buffer[index])

  // Set the byte at the specified index to the new value
  buffer[index] = newByte

  return buffer
}
