import z32 from 'z32'
import crypto from 'hypercore-crypto'

export function createInvite (secretKey, opts = {}) {
  const parts = createInviteParts(secretKey, opts)
  const invite = encodeInviteParts(parts)
  return { invite, parts }
}

export function createInviteParts (secretKey, opts = {}) {
  const now = opts.now || Date.now()
  const topic = opts.topic || crypto.randomBytes(32)
  const expirationInHours = opts.expirationInHours || 24
  const expirationTimestamp = now + expirationInHours * 60 * 60 * 1000
  const expirationBuffer = Buffer.from(expirationTimestamp.toString())
  // use or create a random topic key

  // join the topic and expiriationTimestamp into a buffer
  const topicAndExpiration = Buffer.concat([topic, expirationBuffer])
  const signature = crypto.sign(topicAndExpiration, secretKey)
  return { topic, expirationBuffer, signature }
}

export function encodeInviteParts (parts) {
  return z32.encode(Buffer.concat([parts.topic, parts.expirationBuffer, parts.signature]))
}

export function decodeInvite(inviteBase32) {
  try {
    return { ok: true, buffer: z32.decode(inviteBase32) }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

export function getParts(inviteBase32) {
  const decoded = decodeInvite(inviteBase32)
  if (!decoded.ok) {
    return { ok: false, error: decoded.error }
  }
  return getPartsFromBuffer(decoded.buffer)
}

export function getPartsFromBuffer(invite) {
  const parts = { ok: false }
  if (invite.length !== 32 + 13 + 64) {
    parts.error = 'malformed invite length'
    return parts // ok is false
  }
  parts.ok = true
  parts.topicAndExpiration = invite.slice(0, 32 + 13)
  parts.topic = invite.slice(0, 32)
  try {
    parts.expirationTimestamp = parseInt(invite.slice(32).toString())
  } catch (e) {
    parts.error = 'invalid expiration timestamp'
    return parts // ok is false
  }
  parts.signature = invite.slice(32 + 13)
  return parts
}

export function verifyInviteBuffer(publicKey, inviteBuffer, opts = {}) {
  const now = opts.now || Date.now()
  const results = {}
  const parts = getPartsFromBuffer(inviteBuffer)
  if (!parts.ok) {
    results.malformed = true
    results.error = parts.error
    return results
  }
  results.malformed = false
  try {
    results.signedFailed = !crypto.verify(parts.topicAndExpiration, parts.signature, publicKey)
  } catch (e) {
    results.signedFailed = true
    return results
  }
  if (results.signedFailed) return results
  results.expired = parts.expirationTimestamp < now
  return results
}

export function verifyInvite(publicKey, inviteBase32, opts = {}) {
  const decoded = decodeInvite(inviteBase32)
  if (!decoded.ok) {
    return { malformed: true, error: decoded.error }
  }
  return verifyInviteBuffer(publicKey, decoded.buffer, opts)
}
