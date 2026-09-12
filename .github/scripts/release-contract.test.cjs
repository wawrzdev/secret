'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const { createHash } = require('node:crypto')
const { expectedNames, validateDraft, assertNewVersion } = require('./release-contract.cjs')

function fixture(app = 'secret') {
  const tag = 'v0.1.0'
  const commit = 'a'.repeat(40)
  const files = new Map(expectedNames(app, tag).filter(name => name !== 'checksums.txt').map(name => [name, Buffer.from(name)]))
  const hash = bytes => createHash('sha256').update(bytes).digest('hex')
  files.set('checksums.txt', Buffer.from([...files].map(([name, bytes]) => `${hash(bytes)}  ${name}\n`).join('')))
  const release = { draft: true, prerelease: false, tag_name: tag, target_commitish: commit,
    assets: [...files].map(([name, bytes]) => ({ name, state: 'uploaded', size: bytes.length, digest: `sha256:${hash(bytes)}` })) }
  return { release, files, app, tag, commit }
}
function validate(f) { validateDraft(f.release, f.app, f.tag, f.commit, f.files) }

test('accepts all three complete draft contracts', () => {
  for (const app of ['secret', 'snip', 'wtf']) assert.doesNotThrow(() => validate(fixture(app)))
})
test('rejects incomplete or duplicate uploaded assets', () => {
  let f = fixture(); f.release.assets.pop(); assert.throws(() => validate(f), /nine assets/)
  f = fixture(); f.release.assets[1] = f.release.assets[0]; assert.throws(() => validate(f), /nine assets/)
})
test('rejects remote corruption before publishing', () => {
  const f = fixture(); f.release.assets[0].digest = `sha256:${'0'.repeat(64)}`
  assert.throws(() => validate(f), /differs from local bytes/)
})
test('rejects incorrect checksum content even when its upload digest matches', () => {
  const f = fixture(); const bytes = Buffer.from('0'.repeat(64) + '  wrong-name\n')
  f.files.set('checksums.txt', bytes)
  const asset = f.release.assets.find(asset => asset.name === 'checksums.txt')
  asset.size = bytes.length; asset.digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`
  assert.throws(() => validate(f), /checksum list/)
})
test('never republishes an existing final release or a different source commit', () => {
  let f = fixture(); f.release.draft = false; assert.throws(() => validate(f), /not a draft/)
  f = fixture(); f.release.target_commitish = 'b'.repeat(40); assert.throws(() => validate(f), /not a draft/)
  assert.throws(() => expectedNames('secret', 'v0.1.0-rc1'), /stable version tag/)
})

test('only advances the latest stable version monotonically', () => {
  assert.doesNotThrow(() => assertNewVersion('v0.2.0', 'v0.1.9'))
  assert.doesNotThrow(() => assertNewVersion('v1.0.0', 'v0.99.99'))
  for (const tag of ['v0.1.9', 'v0.1.8', 'v0.1.10-rc1']) {
    assert.throws(() => assertNewVersion(tag, 'v0.1.9'))
  }
})
