## Chacha20 
##
## TODO:
## - dont copy state.. use something like slices
## - implement an iterator for retrieving the next key stream block (usage as CPRNG)
## - clear context (memory)

# import math
import utils

type
  Chacha20* = object
    original_state*: array[16, uint32] # make privat in the future... public for testing
    state*: array[16, uint32]

## init state via uint32 state array
proc init*(ctx: var Chacha20, state: array[16, uint32]) =
  ctx.original_state = state
  ctx.state = state

## init state via byte input
proc init*(ctx:  var Chacha20, key: openArray[byte], nonce: openArray[byte], counter: uint32) =
  ctx.original_state = [
   0x61707865'u32,    0x3320646e,         0x79622d32,         0x6b206574,
   leLoad32(key, 0),  leLoad32(key, 4),   leLoad32(key, 8),   leLoad32(key, 12),
   leLoad32(key, 16), leLoad32(key, 20),  leLoad32(key, 24),  leLoad32(key, 28),
   counter,           leLoad32(nonce, 0), leLoad32(nonce, 4), leLoad32(nonce, 8),
  ]
  ctx.state = ctx.original_state

# ## init state via uint32 input
# proc init*(ctx:  var Chacha20, key: array[8, uint32], nonce: array[3, uint32], counter: uint32) =
#   ctx.original_state = [0x61707865'u32, 0x3320646e, 0x79622d32, 0x6b206574,
#    key[0],         key[1],         key[2],     key[3],
#    key[4],         key[5],         key[6],     key[7],
#    counter,        nonce[0],       nonce[1],   nonce[2],
#   ]
#   ctx.state = ctx.original_state

proc quater_round_standallone*(a: var uint32, b: var uint32, c: var uint32, d: var uint32): tuple [a: uint32, b: uint32, c: uint32, d: uint32] =
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

proc quater_round*(ctx: var Chacha20, i: int, j: int, k: int, l: int) =
  var a = ctx.state[i]
  var b = ctx.state[j]
  var c = ctx.state[k]
  var d = ctx.state[l]
  
  (a,b,c,d) = quater_round_standallone(a, b, c, d)
  
  ctx.state[i] = a
  ctx.state[j] = b
  ctx.state[k] = c
  ctx.state[l] = d

proc inner_block*(ctx: var Chacha20) =
  ctx.quater_round(0, 4, 8, 12)
  ctx.quater_round(1, 5, 9, 13)
  ctx.quater_round(2, 6, 10, 14)
  ctx.quater_round(3, 7, 11, 15)
  ctx.quater_round(0, 5, 10, 15)
  ctx.quater_round(1, 6, 11, 12)
  ctx.quater_round(2, 7, 8, 13)
  ctx.quater_round(3, 4, 9, 14)

proc chacha20_block*(ctx: var Chacha20) =
  for i in 1..10:
    ctx.inner_block()

proc add_original_state*(ctx: var Chacha20) =
  for i in 0..15:
    ctx.state[i] += ctx.original_state[i]

proc reset_state_and_increment_counter*(ctx: var Chacha20) =
  ctx.state = ctx.original_state # TODO: use memory map for this copy (maybe its done it is already implemented in an efficient way?)
  inc ctx.original_state[12]
  inc ctx.state[12]

proc export_state_bytes*(ctx: var Chacha20, dst: var openArray[byte]) =
  for i in 0..15:
    leStore32(dst, i*4, ctx.state[i])

## TODO: this will be the full round... maybe rename this to chacha20_block
proc chacha20_block_round*(ctx: var Chacha20, key_stream: var openArray[byte]) =
  ctx.chacha20_block()
  ctx.add_original_state()
  ctx.export_state_bytes(key_stream)
  ctx.reset_state_and_increment_counter()


## encrypt using chacha
## This will become the actual interface...
## TODO: think about the interface... this is just implementing basic funtionality and making the test vector work
## TODO: should we offer inplace encryption?
proc chacha20_encrypt*(key: openArray[byte], counter: uint32, nonce: openArray[byte], plainTextBytes: openArray[byte], cipherTextBytes: var openArray[byte]) =
  # check input
  if len(plainTextBytes) == 0: return
  #init ctx
  var ctx = Chacha20()
  ctx.init(key, nonce, counter)
  let num_blocks = len(plainTextBytes) div 64
  var key_stream = newSeq[byte](64)

  # blocks of 64 bit size
  for j in 0..num_blocks-1:
    ctx.chacha20_block_round(key_stream) # this comprises increasing the counter
    for i in (j*64)..(j*64)+63:
      # TODO: don't mod here... make it more efficient
      cipherTextBytes[i] = key_stream[i mod 64] xor plainTextBytes[i]
  # remainder
  if((len plainTextBytes) mod 64 != 0):
    ctx.chacha20_block_round(key_stream)
    var j = num_blocks
    for i in j*64..len(plainTextBytes)-1:
      cipherTextBytes[i] = key_stream[i mod 64] xor plainTextBytes[i]


# ## TODO: should we offer this as an interfact, too?
# proc chacha20_encrypt_string*(key: openArray[byte], counter: uint32, nonce: openArray[byte], plaintext: string): string =
#   var plainTextBytes = newSeq[byte](len(plaintext))
#   var encText = newSeq[byte](len(plaintext))
#   copyMem(addr plainTextBytes[0], addr plaintext[0], len(plaintext))





