'use strict'

const { createHash } = require('node:crypto')

function expectedNames(app, tag) {
  if (!['secret', 'snip', 'wtf'].includes(app) || !/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)) {
    throw new Error('unsupported application or stable version tag')
  }
  const version = tag.slice(1)
  const names = ['checksums.txt']
  for (const arch of ['amd64', 'arm64']) {
    for (const os of ['darwin', 'linux']) names.push(`${app}_${version}_${os}_${arch}.tar.gz`)
    for (const extension of ['deb', 'pkg.tar.zst']) names.push(`${app}_${version}_linux_${arch}.${extension}`)
  }
  return names.sort()
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex')
}

function validateDraft(release, app, tag, commit, files) {
  if (!release.draft || release.prerelease || release.tag_name !== tag || release.target_commitish !== commit) {
    throw new Error('release is not a draft for the exact source commit and stable tag')
  }
  const expected = expectedNames(app, tag)
  const assets = new Map(release.assets.map(asset => [asset.name, asset]))
  if (release.assets.length !== expected.length || assets.size !== expected.length || expected.some(name => !assets.has(name))) {
    throw new Error('draft does not contain exactly the expected nine assets')
  }
  if (files.size !== expected.length || expected.some(name => !files.has(name))) throw new Error('local artifacts are incomplete')
  for (const name of expected) {
    const asset = assets.get(name)
    const bytes = files.get(name)
    if (asset.state !== 'uploaded' || asset.size !== bytes.length || asset.digest !== `sha256:${sha256(bytes)}`) {
      throw new Error(`uploaded asset differs from local bytes: ${name}`)
    }
  }
  const checksums = new Map()
  for (const line of files.get('checksums.txt').toString('utf8').trimEnd().split('\n')) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9._+-]+)$/.exec(line)
    if (!match || checksums.has(match[2])) throw new Error('malformed or duplicate checksum entry')
    checksums.set(match[2], match[1])
  }
  if (checksums.size !== expected.length - 1) throw new Error('checksum list has missing or extra entries')
  for (const name of expected.filter(name => name !== 'checksums.txt')) {
    if (checksums.get(name) !== sha256(files.get(name))) throw new Error(`checksum mismatch: ${name}`)
  }
}

function assertNewVersion(tag, latestTag) {
  const pattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
  const candidate = pattern.exec(tag)
  const current = pattern.exec(latestTag)
  if (!candidate || !current) throw new Error('latest/candidate version is not stable semver')
  for (let index = 1; index <= 3; index++) {
    if (BigInt(candidate[index]) > BigInt(current[index])) return
    if (BigInt(candidate[index]) < BigInt(current[index])) break
  }
  throw new Error('release must be newer than the current latest version')
}

module.exports = { expectedNames, validateDraft, assertNewVersion }
