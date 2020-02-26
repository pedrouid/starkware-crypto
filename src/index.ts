/////////////////////////////////////////////////////////////////////////////////
// Copyright 2019 StarkWare Industries Ltd.                                    //
//                                                                             //
// Licensed under the Apache License, Version 2.0 (the "License").             //
// You may not use this file except in compliance with the License.            //
// You may obtain a copy of the License at                                     //
//                                                                             //
// https://www.starkware.co/open-source-license/                               //
//                                                                             //
// Unless required by applicable law or agreed to in writing,                  //
// software distributed under the License is distributed on an "AS IS" BASIS,  //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    //
// See the License for the specific language governing permissions             //
// and limitations under the License.                                          //
/////////////////////////////////////////////////////////////////////////////////

import BN from 'bn.js';
import hash from 'hash.js';
import * as elliptic from 'elliptic';
import assert from 'assert';
import constantPointsHex from './constantPoints';

/* --------------------------- TYPINGS ---------------------------------- */

export type KeyPair = elliptic.ec.KeyPair;

export type MessageParams = {
  instructionTypeBn: BN;
  vault0Bn: BN;
  vault1Bn: BN;
  amount0Bn: BN;
  amount1Bn: BN;
  nonceBn: BN;
  expirationTimestampBn: BN;
};

/* --------------------------- ELLIPTIC ---------------------------------- */

export const prime = new BN(
  '800000000000011000000000000000000000000000000000000000000000001',
  16
);

const starkEc = new elliptic.ec(
  new elliptic.curves.PresetCurve({
    type: 'short',
    prime: null,
    p: prime as any,
    a:
      '00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001',
    b:
      '06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89',
    n:
      '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
    hash: hash.sha256,
    gRed: false,
    g: constantPointsHex[1],
  })
);
export const ec = starkEc;

/* --------------------------- CONSTANTS ---------------------------------- */

export const constantPoints = constantPointsHex.map(coords =>
  starkEc.curve.point(new BN(coords[0], 16), new BN(coords[1], 16))
);
export const shiftPoint = constantPoints[0];

const ZERO_BN = new BN('0');
const ONE_BN = new BN('1');
const TWO_POW_22_BN = new BN('400000', 16);
const TWO_POW_31_BN = new BN('80000000', 16);
const TWO_POW_63_BN = new BN('8000000000000000', 16);

const MISSING_HEX_PREFIX = 'Hex strings expected to be prefixed with 0x.';

/* --------------------------- PRIVATE ---------------------------------- */

function isHexPrefixed(str: string) {
  return str.substring(0, 2) === '0x';
}

function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/, '');
}

function addHexPrefix(hex: string): string {
  return isHexPrefixed(hex) ? hex : `0x${hex}`;
}

function sanitizeHex(hex: string): string {
  hex = removeHexPrefix(hex);
  if (hex === '') {
    return '';
  }
  hex = hex.length % 2 !== 0 ? '0' + hex : hex;
  return addHexPrefix(hex);
}

function pedersen(input: string[]): string {
  const ZERO_BN = new BN('0');
  const one = new BN('1');
  let point = shiftPoint;
  for (let i = 0; i < input.length; i++) {
    let x = new BN(input[i], 16);
    assert(x.gte(ZERO_BN) && x.lt(prime), 'Invalid input: ' + input[i]);
    for (let j = 0; j < 252; j++) {
      const pt = constantPoints[2 + i * 252 + j];
      assert(!point.getX().eq(pt.getX()));
      if (x.and(one).toNumber() !== 0) {
        point = point.add(pt);
      }
      x = x.shrn(1);
    }
  }
  return point.getX().toString(16);
}

function hashMessage(
  serialized: string,
  token0: string,
  token1OrPubKey: string
) {
  return pedersen([pedersen([token0, token1OrPubKey]), serialized]);
}

/*
 The function _truncateToN in lib/elliptic/ec/index.js does a shift-right of 4 bits
 in some cases. This function does the opposite operation so that
   _truncateToN(fixMessage(msg)) == msg.
*/
function fixMessage(msg: string) {
  // remove hex prefix
  msg = removeHexPrefix(msg);

  // Convert to BN to remove leading zeros.
  msg = new BN(msg, 16).toString(16);

  if (msg.length <= 62) {
    // In this case, msg should not be transformed, as the byteLength() is at most 31,
    // so delta < 0 (see _truncateToN).
    return msg;
  }
  assert(msg.length === 63);
  // In this case delta will be 4 so we perform a shift-left of 4 bits by adding a ZERO_BN.
  return msg + '0';
}

/* --------------------------- PUBLIC ---------------------------------- */

export function getKeyPair(privateKey: string): KeyPair {
  return starkEc.keyFromPrivate(privateKey, 'hex');
}

export function getStarkKey(publicKey: string): string {
  const keyPair = starkEc.keyFromPublic(publicKey, 'hex');
  const starkKeyBn = (keyPair as any).pub.getX();
  return sanitizeHex(starkKeyBn.toString(16));
}

export function getPrivate(keyPair: KeyPair): string {
  return keyPair.getPrivate('hex');
}

export function getPublic(keyPair: KeyPair): string {
  return keyPair.getPublic(true, 'hex');
}

export function deserializeMessage(serialized: string): MessageParams {
  serialized = removeHexPrefix(serialized);
  const slice0 = 0;
  const slice1 = slice0 + 1;
  const slice2 = slice1 + 31;
  const slice3 = slice2 + 31;
  const slice4 = slice3 + 63;
  const slice5 = slice4 + 63;
  const slice6 = slice5 + 31;
  const slice7 = slice6 + 22;

  return {
    instructionTypeBn: new BN(serialized.substring(slice0, slice1), 16),
    vault0Bn: new BN(serialized.substring(slice1, slice2), 16),
    vault1Bn: new BN(serialized.substring(slice2, slice3), 16),
    amount0Bn: new BN(serialized.substring(slice3, slice4), 16),
    amount1Bn: new BN(serialized.substring(slice4, slice5), 16),
    nonceBn: new BN(serialized.substring(slice5, slice6), 16),
    expirationTimestampBn: new BN(serialized.substring(slice6, slice7), 16),
  };
}

export function serializeMessage(
  instructionTypeBn: BN,
  vault0Bn: BN,
  vault1Bn: BN,
  amount0Bn: BN,
  amount1Bn: BN,
  nonceBn: BN,
  expirationTimestampBn: BN
): string {
  let serialized = instructionTypeBn;
  serialized = serialized.ushln(31).add(vault0Bn);
  serialized = serialized.ushln(31).add(vault1Bn);
  serialized = serialized.ushln(63).add(amount0Bn);
  serialized = serialized.ushln(63).add(amount1Bn);
  serialized = serialized.ushln(31).add(nonceBn);
  serialized = serialized.ushln(22).add(expirationTimestampBn);
  return sanitizeHex(serialized.toString(16));
}

export function formatMessage(
  instruction: 'transfer' | 'order',
  vault0: string,
  vault1: string,
  amount0: string,
  amount1: string,
  token0: string,
  token1: string,
  nonce: string,
  expirationTimestamp: string
): string {
  const isTransfer = instruction === 'transfer';

  assert(isHexPrefixed(token0) && isHexPrefixed(token1), MISSING_HEX_PREFIX);

  const vault0Bn = new BN(vault0);
  const vault1Bn = new BN(vault1);
  const amount0Bn = new BN(amount0, 10);
  const amount1Bn = new BN(amount1, 10);
  const token0Bn = new BN(removeHexPrefix(token0), 16);
  const token1Bn = new BN(removeHexPrefix(token1), 16);
  const nonceBn = new BN(nonce);
  const expirationTimestampBn = new BN(expirationTimestamp);

  assert(vault0Bn.gte(ZERO_BN));
  assert(vault1Bn.gte(ZERO_BN));
  assert(amount0Bn.gte(ZERO_BN));
  if (!isTransfer) {
    assert(amount1Bn.gte(ZERO_BN));
  }
  assert(token0Bn.gte(ZERO_BN));
  assert(token1Bn.gte(ZERO_BN));
  assert(nonceBn.gte(ZERO_BN));
  assert(expirationTimestampBn.gte(ZERO_BN));

  assert(vault0Bn.lt(TWO_POW_31_BN));
  assert(vault1Bn.lt(TWO_POW_31_BN));
  assert(amount0Bn.lt(TWO_POW_63_BN));
  assert(amount1Bn.lt(TWO_POW_63_BN));
  assert(token0Bn.lt(prime));
  assert(token1Bn.lt(prime));
  assert(nonceBn.lt(TWO_POW_31_BN));
  assert(expirationTimestampBn.lt(TWO_POW_22_BN));

  const instructionTypeBn = isTransfer ? ONE_BN : ZERO_BN;

  return serializeMessage(
    instructionTypeBn,
    vault0Bn,
    vault1Bn,
    amount0Bn,
    amount1Bn,
    nonceBn,
    expirationTimestampBn
  );
}

/*
 Serializes the order message in the canonical format expected by the verifier.
 party_a sells amountSell coins of tokenSell from vaultSell.
 party_a buys amountBuy coins of tokenBuy into vaultBuy.

 Expected types:
 ---------------
 vaultSell, vaultBuy - uint31 (as int)
 amountSell, amountBuy - uint63 (as decimal string)
 tokenSell, tokenBuy - uint256 field element strictly less than the prime (as hex string with 0x)
 nonce - uint31 (as int)
 expirationTimestamp - uint22 (as int).
*/
export function getLimitOrderMsg(
  vaultSell: string,
  vaultBuy: string,
  amountSell: string,
  amountBuy: string,
  tokenSell: string,
  tokenBuy: string,
  nonce: string,
  expirationTimestamp: string
): string {
  const serialized = formatMessage(
    'order',
    vaultSell,
    vaultBuy,
    amountSell,
    amountBuy,
    tokenSell,
    tokenBuy,
    nonce,
    expirationTimestamp
  );
  return hashMessage(
    removeHexPrefix(serialized),
    removeHexPrefix(tokenSell),
    removeHexPrefix(tokenBuy)
  );
}

/*
 Serializes the transfer message in the canonical format expected by the verifier.
 The sender transfer 'amount' coins of 'token' from vault with id senderVaultId to vault with id
 receiverVaultId. The receiver's public key is receiverPublicKey.
 Expected types:
 ---------------
 amount - uint63 (as decimal string)
 nonce - uint31 (as int)
 senderVaultId uint31 (as int)
 token - uint256 field element strictly less than the prime (as hex string with 0x)
 receiverVaultId - uint31 (as int)
 receiverPublicKey - uint256 field element strictly less than the prime (as hex string with 0x)
 expirationTimestamp - uint22 (as int).
*/
export function getTransferMsg(
  amount: string,
  nonce: string,
  senderVaultId: string,
  token: string,
  receiverVaultId: string,
  receiverPublicKey: string,
  expirationTimestamp: string
) {
  const serialized = formatMessage(
    'transfer',
    senderVaultId,
    receiverVaultId,
    amount,
    ZERO_BN.toString(),
    token,
    receiverPublicKey,
    nonce,
    expirationTimestamp
  );
  return hashMessage(
    removeHexPrefix(serialized),
    removeHexPrefix(token),
    removeHexPrefix(receiverPublicKey)
  );
}

/*
 Signs a message using the provided key.
 key should be an elliptic.keyPair with a valid private key.
 Returns an elliptic.Signature.
*/
export function sign(keyPair: KeyPair, msg: string): elliptic.ec.Signature {
  return keyPair.sign(fixMessage(msg));
}

/*
 Verifies a message using the provided key.
 key should be an elliptic.keyPair with a valid public key.
 msgSignature should be an elliptic.Signature.
 Returns a boolean true if the verification succeeds.
*/
export function verify(
  keyPair: KeyPair,
  msg: string,
  sig: elliptic.SignatureInput
): boolean {
  return keyPair.verify(fixMessage(msg), sig);
}
