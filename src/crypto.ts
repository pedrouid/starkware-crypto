import BN from 'bn.js';
import hashJS from 'hash.js';
import assert from 'assert';
import * as RSV from 'rsv-signature';
import * as bip39 from 'bip39';
import * as elliptic from 'elliptic';
import * as encUtils from 'enc-utils';
import { keccak_256 } from 'js-sha3';
import { hdkey } from 'ethereumjs-wallet';

import {
  Token,
  ERC20TokenData,
  ERC721TokenData,
  KeyPair,
  MessageParams,
  Signature,
  SignatureInput,
} from './types';
import { constantPointsHex } from './constants';

/* --------------------------- ELLIPTIC ---------------------------------- */

export const prime = new BN(
  '800000000000011000000000000000000000000000000000000000000000001',
  16
);

export const order = new BN(
  '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
  16
);

export const secpOrder = new BN(
  'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141',
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
    n: order as any,
    hash: hashJS.sha256,
    gRed: false,
    g: constantPointsHex[1],
  })
);
export const ec = starkEc;

/* --------------------------- CONSTANTS ---------------------------------- */

export const constantPoints = constantPointsHex.map((coords: string[]) =>
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

function pedersen(input) {
  let point = shiftPoint;
  for (let i = 0; i < input.length; i++) {
    let x = new BN(encUtils.removeHexPrefix(input[i]), 16);
    assert(x.gte(ZERO_BN) && x.lt(prime), 'Invalid input: ' + input[i]);
    for (let j = 0; j < 252; j++) {
      const pt = constantPoints[2 + i * 252 + j];
      assert(!point.getX().eq(pt.getX()));
      if (x.and(ONE_BN).toNumber() !== 0) {
        point = point.add(pt);
      }
      x = x.shrn(1);
    }
  }
  return point.getX().toString(16);
}

function isCompressedPublicKey(hex: string) {
  hex = encUtils.removeHexPrefix(hex);
  return hex.length === 66 && (hex.startsWith('03') || hex.startsWith('02'));
}

function checkHexValue(hex: string) {
  assert(isHexPrefixed(hex), MISSING_HEX_PREFIX);
  const hexBn = new BN(encUtils.removeHexPrefix(hex), 16);
  assert(hexBn.gte(ZERO_BN));
  assert(hexBn.lt(prime));
}

function parseTokenInput(input: Token | string) {
  if (typeof input === 'string') {
    if (isCompressedPublicKey(input)) {
      return getXCoordinate(input);
    }
    checkHexValue(input);
    return input;
  }
  return hashTokenId(input);
}

/*
 The function _truncateToN in lib/elliptic/ec/index.js does a shift-right of 4 bits
 in some cases. This function does the opposite operation so that
   _truncateToN(fixMessage(msg)) == msg.
*/
function fixMessage(msg: string) {
  // remove hex prefix
  msg = encUtils.removeHexPrefix(msg);

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

function hashKeyWithIndex(key: string, index: number): BN {
  return new BN(
    hashJS
      .sha256()
      .update(
        encUtils.hexToBuffer(
          encUtils.removeHexPrefix(key) +
            encUtils.sanitizeBytes(encUtils.numberToHex(index), 2)
        )
      )
      .digest('hex'),
    16
  );
}

function grindKey(privateKey: string): string {
  let i = 0;
  let key: BN = hashKeyWithIndex(privateKey, i);

  while (!key.lt(secpOrder.sub(secpOrder.mod(order)))) {
    key = hashKeyWithIndex(key.toString(16), i);
    i = i++;
  }
  return key.mod(order).toString('hex');
}

function getIntFromBits(
  hex: string,
  start: number,
  end: number | undefined = undefined
): number {
  let bin = encUtils.hexToBinary(hex);
  let bits = bin.slice(start, end);
  let int = encUtils.binaryToNumber(bits);
  return int;
}

/* --------------------------- PUBLIC ---------------------------------- */

export function getAccountPath(
  layer: string,
  application: string,
  ethereumAddress: string,
  index: string
): string {
  const layerHash = hashJS
    .sha256()
    .update(layer)
    .digest('hex');
  const applicationHash = hashJS
    .sha256()
    .update(application)
    .digest('hex');
  const layerInt = getIntFromBits(layerHash, -31);
  const applicationInt = getIntFromBits(applicationHash, -31);
  const ethAddressInt1 = getIntFromBits(ethereumAddress, -31);
  const ethAddressInt2 = getIntFromBits(ethereumAddress, -62, -31);
  return `m/2645'/${layerInt}'/${applicationInt}'/${ethAddressInt1}'/${ethAddressInt2}'/${index}`;
}

export function getKeyPairFromPath(mnemonic: string, path: string): KeyPair {
  const seed = bip39.mnemonicToSeedSync(mnemonic).toString('hex');
  const privateKey = hdkey
    .fromMasterSeed(Buffer.from(seed, 'hex'))
    .derivePath(path)
    .getWallet()
    .getPrivateKeyString();
  return getKeyPair(grindKey(privateKey));
}

export function getKeyPair(privateKey: string): KeyPair {
  return starkEc.keyFromPrivate(privateKey, 'hex');
}

export function getKeyPairFromPublicKey(publicKey: string): KeyPair {
  return starkEc.keyFromPublic(encUtils.hexToArray(publicKey));
}

export function getPrivate(keyPair: KeyPair): string {
  return keyPair.getPrivate('hex');
}

export function getPublic(keyPair: KeyPair, compressed = false): string {
  return keyPair.getPublic(compressed, 'hex');
}

export function getStarkPublicKey(keyPair: KeyPair): string {
  return getPublic(keyPair, true);
}

export function getXCoordinate(publicKey: string): string {
  const keyPair = getKeyPairFromPublicKey(publicKey);
  return encUtils.sanitizeBytes((keyPair as any).pub.getX().toString(16), 2);
}

export function getYCoordinate(publicKey: string): string {
  const keyPair = getKeyPairFromPublicKey(publicKey);
  return encUtils.sanitizeBytes((keyPair as any).pub.getY().toString(16), 2);
}

export function hashTokenId(token: Token) {
  let id: string;
  let tokenAddress: string;
  switch (token.type.toUpperCase()) {
    case 'ETH':
      id = 'ETH()';
      break;
    case 'ERC20':
      tokenAddress = (token.data as ERC20TokenData).tokenAddress;
      checkHexValue(tokenAddress);
      id = `ERC20Token(${tokenAddress})`;
      break;
    case 'ERC721':
      tokenAddress = (token.data as ERC721TokenData).tokenAddress;
      checkHexValue(tokenAddress);
      id = `ERC721Token(${tokenAddress})`;
      break;
    default:
      throw new Error(`Unknown token type: ${token.type}`);
  }
  return encUtils.sanitizeHex(keccak_256(id).slice(2, 10));
}

export function hashMessage(w1: string, w2: string, w3: string) {
  return pedersen([pedersen([w1, w2]), w3]);
}

export function deserializeMessage(serialized: string): MessageParams {
  serialized = encUtils.removeHexPrefix(serialized);
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
  return encUtils.sanitizeHex(serialized.toString(16));
}

export function formatMessage(
  instruction: 'transfer' | 'order',
  vault0: string,
  vault1: string,
  amount0: string,
  amount1: string,
  nonce: string,
  expirationTimestamp: string
): string {
  const isTransfer = instruction === 'transfer';

  const vault0Bn = new BN(vault0);
  const vault1Bn = new BN(vault1);
  const amount0Bn = new BN(amount0, 10);
  const amount1Bn = new BN(amount1, 10);
  const nonceBn = new BN(nonce);
  const expirationTimestampBn = new BN(expirationTimestamp);

  assert(vault0Bn.gte(ZERO_BN));
  assert(vault1Bn.gte(ZERO_BN));
  assert(amount0Bn.gte(ZERO_BN));
  if (!isTransfer) {
    assert(amount1Bn.gte(ZERO_BN));
  }
  assert(nonceBn.gte(ZERO_BN));
  assert(expirationTimestampBn.gte(ZERO_BN));

  assert(vault0Bn.lt(TWO_POW_31_BN));
  assert(vault1Bn.lt(TWO_POW_31_BN));
  assert(amount0Bn.lt(TWO_POW_63_BN));
  assert(amount1Bn.lt(TWO_POW_63_BN));
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

export function getLimitOrderMsg(
  vaultSell: string,
  vaultBuy: string,
  amountSell: string,
  amountBuy: string,
  tokenSell: Token,
  tokenBuy: Token,
  nonce: string,
  expirationTimestamp: string
): string {
  const w1 = parseTokenInput(tokenSell);
  const w2 = parseTokenInput(tokenBuy);
  const w3 = formatMessage(
    'order',
    vaultSell,
    vaultBuy,
    amountSell,
    amountBuy,
    nonce,
    expirationTimestamp
  );
  return hashMessage(w1, w2, w3);
}

export function getTransferMsg(
  amount: string,
  nonce: string,
  senderVaultId: string,
  token: Token,
  receiverVaultId: string,
  receiverPublicKey: string,
  expirationTimestamp: string
): string {
  const w1 = parseTokenInput(token);
  const w2 = parseTokenInput(receiverPublicKey);
  const w3 = formatMessage(
    'transfer',
    senderVaultId,
    receiverVaultId,
    amount,
    ZERO_BN.toString(),
    nonce,
    expirationTimestamp
  );
  return hashMessage(w1, w2, w3);
}

/*
 Signs a message using the provided key.
 key should be an KeyPair with a valid private key.
 Returns an Signature.
*/
export function sign(keyPair: KeyPair, msg: string): Signature {
  return keyPair.sign(fixMessage(msg));
}

/*
 Verifies a message using the provided key.
 key should be an KeyPair with a valid public key.
 msgSignature should be an Signature.
 Returns a boolean true if the verification succeeds.
*/
export function verify(
  keyPair: KeyPair,
  msg: string,
  sig: SignatureInput
): boolean {
  return keyPair.verify(fixMessage(msg), sig);
}

export function compress(publicKey: string): string {
  return getKeyPairFromPublicKey(publicKey).getPublic(true, 'hex');
}

export function decompress(publicKey: string): string {
  return getKeyPairFromPublicKey(publicKey).getPublic(false, 'hex');
}

export function verifyStarkPublicKey(
  starkPublicKey: string,
  msg: string,
  sig: SignatureInput
): boolean {
  const keyPair = getKeyPairFromPublicKey(starkPublicKey);
  return verify(keyPair, msg, sig);
}

export const exportRecoveryParam = RSV.exportRecoveryParam;

export const importRecoveryParam = RSV.importRecoveryParam;

export const serializeSignature = RSV.serializeSignature;

export const deserializeSignature = RSV.deserializeSignature;
