#  nim chacha20
#  author: kais3r

## This module implements the Chacha20 algorithm by D.J. Bernstein
## as specified in RFC8439
## [https://datatracker.ietf.org/doc/html/rfc8439]

##
## TODO:
## - Security
##    - clear context (memory)
## - Code/Design
##    - reasonable public interface (currently, almost everything is public for testing)
## - Optimization
##    - zero copy where possible
##    - inlining / remove unnecessary calls
##    - inplace encryption? (as an alternative)
##    - SIMD instructions

## - Future Feature List
##    - extend API to allow retrieving a keystream (e.g. for usage as a CPRNG)
##      - implement with iterators for retrieving the next key stream block

import system

import utils

type
  Chacha20* = object
    originalState*: array[16, uint32]
    state*: array[16, uint32]

proc init*(ctx: var Chacha20, state: array[16, uint32]) =
  ## initialize the state directly via passing a uint32 state array
  ctx.originalState = state
  ctx.state = state

proc init*(ctx:  var Chacha20, key: openArray[byte], nonce: openArray[byte], counter: uint32) =
  ## initialize the state via separate byte arrays for the key and nonce
  ctx.originalState = [
   0x61707865'u32,    0x3320646e,         0x79622d32,         0x6b206574,
   leLoad32(key, 0),  leLoad32(key, 4),   leLoad32(key, 8),   leLoad32(key, 12),
   leLoad32(key, 16), leLoad32(key, 20),  leLoad32(key, 24),  leLoad32(key, 28),
   counter,           leLoad32(nonce, 0), leLoad32(nonce, 4), leLoad32(nonce, 8),
  ]
  ctx.state = ctx.originalState

# TODO: do we want this as an interface?
# proc init*(ctx:  var Chacha20, key: array[8, uint32], nonce: array[3, uint32], counter: uint32) =
#   ## init state via separate uint32 arrays for key and nonce
#   ctx.originalState = [0x61707865'u32, 0x3320646e, 0x79622d32, 0x6b206574,
#    key[0],         key[1],         key[2],     key[3],
#    key[4],         key[5],         key[6],     key[7],
#    counter,        nonce[0],       nonce[1],   nonce[2],
#   ]
#   ctx.state = ctx.originalState

proc quaterRoundStandallone*(a: var uint32, b: var uint32, c: var uint32, d: var uint32): tuple [a: uint32, b: uint32, c: uint32, d: uint32] =
  ## public just for testing
  a = a + b # wrapping add, overflow desired
  d = d xor a
  d = ROL(d, 16)
  c = c + d
  b = b xor c;
  b = ROL(b, 12);
  a = a + b
  d = d xor a
  d = ROL(d, 8)
  c = c + d
  b = b xor c;
  b = ROL(b, 7)
  
  (a, b, c, d)

proc quaterRound*(ctx: var Chacha20, i: int, j: int, k: int, l: int) =
  ## public just for testing
  var a = ctx.state[i]
  var b = ctx.state[j]
  var c = ctx.state[k]
  var d = ctx.state[l]
  (a,b,c,d) = quaterRoundStandallone(a, b, c, d)
  ctx.state[i] = a
  ctx.state[j] = b
  ctx.state[k] = c
  ctx.state[l] = d

proc innerBlock*(ctx: var Chacha20) =
  ## public just for testing
  ctx.quaterRound(0, 4, 8, 12)
  ctx.quaterRound(1, 5, 9, 13)
  ctx.quaterRound(2, 6, 10, 14)
  ctx.quaterRound(3, 7, 11, 15)
  ctx.quaterRound(0, 5, 10, 15)
  ctx.quaterRound(1, 6, 11, 12)
  ctx.quaterRound(2, 7, 8, 13)
  ctx.quaterRound(3, 4, 9, 14)

proc chacha20BlockRounds*(ctx: var Chacha20) =
  ## public just for testing
  for i in 1..10:
    ctx.innerBlock()

proc addOriginalState*(ctx: var Chacha20) =
  ## public just for testing
  for i in 0..15:
    ctx.state[i] += ctx.originalState[i]

proc chacha20Block*(ctx: var Chacha20) =
  ## public just for testing
  ctx.chacha20BlockRounds()
  ctx.addOriginalState()

proc resetState*(ctx: var Chacha20) =
  ## public just for testing
  ctx.state = ctx.originalState

proc incrementCounter*(ctx: var Chacha20) =
  ## public just for testing
  inc ctx.originalState[12]
  inc ctx.state[12]

proc extractKeyStreamBlock*(ctx: var Chacha20, dst: var openArray[byte]) =
  ## public just for testing
  for i in 0..15:
    leStore32(dst, i*4, ctx.state[i])

proc chacha20BlockFull*(ctx: var Chacha20, keyStreamBlock: var openArray[byte]) =
  ## public just for testing
  ctx.chacha20Block()
  ctx.extractKeyStreamBlock(keyStreamBlock)
  ctx.resetState()
  ctx.incrementCounter()


proc chacha20Encrypt*(key: openArray[byte], counter: uint32, nonce: openArray[byte], plainTextBytes: openArray[byte], cipherTextBytes: var openArray[byte]) =
  ## encrypt a byte array (plainTextBytes) using Chacha20
  ##
  ## counter is used as initial counter value

  # check input
  if len(plainTextBytes) == 0: return
  # init ctx
  var ctx = Chacha20()
  ctx.init(key, nonce, counter)
  let numBlocks = len(plainTextBytes) div 64
  var keyStreamBlock = newSeq[byte](64)
  # encrypt blocks of 64 bit size
  for j in 0..numBlocks-1:
    ctx.chacha20BlockFull(keyStreamBlock) # this comprises increasing the counter
    var k = 0 # TODO: integrate this into the for loop
    for i in (j*64)..(j*64)+63:
      cipherTextBytes[i] = keyStreamBlock[k] xor plainTextBytes[i]
      k += 1
  # encrypt remainder
  if((len plainTextBytes) mod 64 != 0):
    ctx.chacha20BlockFull(keyStreamBlock)
    var j = numBlocks
    for i in j*64..len(plainTextBytes)-1:
      cipherTextBytes[i] = keyStreamBlock[i mod 64] xor plainTextBytes[i]

proc chacha20Decrypt*(key: openArray[byte], counter: uint32, nonce: openArray[byte], cipherTextBytes: openArray[byte], plainTextBytes: var openArray[byte]) =
  chacha20Encrypt(key, counter, nonce, cipherTextBytes, plainTextBytes)


proc chacha20EncryptString*(key: openArray[byte], counter: uint32, nonce: openArray[byte], plaintext: var string): string =
  ## TODO: should we add a string based method to the API?
  var plainTextBytes = newSeq[byte](len(plaintext))
  var cipherTextBytes = newSeq[byte](len(plaintext))
  copyMem(addr plainTextBytes[0], addr plaintext[0], len(plaintext))
  chacha20Encrypt(key, counter, nonce, plainTextBytes, cipherTextBytes)
  toString(cipherTextBytes)

proc chacha20EncryptFile*(key: openArray[byte], counter: uint32, nonce: openArray[byte], ifileName: string, ofileName: string) =
  ## TODO: should we add a file based method to the API?
  var plaintext = readFile(ifileName)
  let ciphertext = chacha20EncryptString(key, counter, nonce, plaintext)
  writeFile(ofileName, ciphertext)

proc chacha20DecryptFile*(key: openArray[byte], counter: uint32, nonce: openArray[byte], ifileName: string, ofileName: string) =
  chacha20EncryptFile(key, counter, nonce, ifileName, ofileName)




