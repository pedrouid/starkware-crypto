import BN from 'bn.js';
import * as elliptic from 'elliptic';

export * from 'starkware-types';

export type BNInput = elliptic.BNInput;

export type KeyPair = elliptic.ec.KeyPair;

export type Signature = elliptic.ec.Signature;

export type SignatureInput = elliptic.SignatureInput;

export type SignatureOptions = elliptic.ec.SignatureOptions;

export type MessageParams = {
  instructionTypeBn: BN;
  vault0Bn: BN;
  vault1Bn: BN;
  amount0Bn: BN;
  amount1Bn: BN;
  nonceBn: BN;
  expirationTimestampBn: BN;
};
