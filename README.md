# starkware-crypto [![npm version](https://badge.fury.io/js/starkware-crypto.svg)](https://badge.fury.io/js/starkware-crypto)

Starkware Crypto Library

## Description

This library is a port from [starkex-resources/\*\*/signature.js](https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature.js).

## Example

```typescript
import * as starkwareCrypto from 'starkware-crypto';

const mnemonic = '';

const path = getAccountPath(
  'starkex',
  'starkexdvf',
  '0x0000000000000000000000000000000000000000',
  '0'
);

const keyPair = starkwareCrypto.getKeyPairFromPath(mnemonic, path);

const publicKey = starkwareCrypto.getPublic(keyPair);

const starkPublicKey = starkwareCrypto.getStarkPublicKey(publicKey);

const msgParams = {
  amount: '2154549703648910716',
  nonce: '1',
  senderVaultId: '34',
  token: {
    type: 'ETH' as starkwareCrypto.TokenTypes,
    data: {
      quantum: '1',
      tokenAddress: '0x89b94e8C299235c00F97E6B0D7368E82d640E848',
    },
  },
  receiverVaultId: '21',
  receiverPublicKey:
    '0x5fa3383597691ea9d827a79e1a4f0f7949435ced18ca9619de8ab97e661020',
  expirationTimestamp: '438953',
};

const message = starkwareCrypto.getTransferMsg(
  msgParams.amount,
  msgParams.nonce,
  msgParams.senderVaultId,
  msgParams.token,
  msgParams.receiverVaultId,
  msgParams.receiverPublicKey,
  msgParams.expirationTimestamp
);

const signature = starkwareCrypto.sign(keyPair, message);

const verified = starkwareCrypto.verify(keyPair, message, signature);
```

## API

```typescript
interface StarkwareCrypto {
  getAccountPath(
    layer: string,
    application: string,
    ethereumAddress: string,
    index: string
  ): string;

  getKeyPairFromPath(mnemonic: string, path: string): KeyPair;

  getKeyPair(privateKey: string): KeyPair;

  getKeyPairFromPublicKey(publicKey: string): KeyPair;

  getPrivate(keyPair: KeyPair): string;

  getPublic(keyPair: KeyPair, compressed: bolean): string;

  getStarkPublicKey(keyPair: KeyPair): string;

  getXCoordinate(publicKey: string): string;

  getYCoordinate(publicKey: string): string;

  hashTokenId(token: Token);

  hashMessage(w1: string, w2: string, w3: string);

  deserializeMessage(serialized: string): MessageParams;

  serializeMessage(
    instructionTypeBn: BN,
    vault0Bn: BN,
    vault1Bn: BN,
    amount0Bn: BN,
    amount1Bn: BN,
    nonceBn: BN,
    expirationTimestampBn: BN
  ): string;

  formatMessage(
    instruction: 'transfer' | 'order',
    vault0: string,
    vault1: string,
    amount0: string,
    amount1: string,
    nonce: string,
    expirationTimestamp: string
  ): string;

  getLimitOrderMsg(
    vaultSell: string,
    vaultBuy: string,
    amountSell: string,
    amountBuy: string,
    tokenSell: Token,
    tokenBuy: Token,
    nonce: string,
    expirationTimestamp: string
  ): string;

  getTransferMsg(
    amount: string,
    nonce: string,
    senderVaultId: string,
    token: Token,
    receiverVaultId: string,
    receiverPublicKey: string,
    expirationTimestamp: string
  ): string;

  sign(keyPair: KeyPair, msg: string): Signature;

  verify(keyPair: KeyPair, msg: string, sig: SignatureInput): boolean;

  verifyStarkPublicKey(
    starkPublicKey: string,
    msg: string,
    sig: SignatureInput
  ): boolean;

  compress(publicKey: string): string;

  decompress(publicKey: string): string;

  exportRecoveryParam(recoveryParam: number | null): string;

  importRecoveryParam(v: string): number;

  serializeSignature(sig: Signature): string;

  deserializeSignature(sig: string): SignatureOptions;
}
```

## Typings

```typescript
type KeyPair = elliptic.ec.KeyPair;

type MessageParams = {
  instructionTypeBn: BN;
  vault0Bn: BN;
  vault1Bn: BN;
  amount0Bn: BN;
  amount1Bn: BN;
  nonceBn: BN;
  expirationTimestampBn: BN;
};

class Signature {
  r: BN;
  s: BN;
  recoveryParam: number | null;

  constructor(options: SignatureInput, enc?: string);

  toDER(enc?: string | null): any;
}

interface SignatureOptions {
  r: BNInput;
  s: BNInput;
  recoveryParam?: number;
}

type BNInput =
  | string
  | BN
  | number
  | Buffer
  | Uint8Array
  | ReadonlyArray<number>;

type SignatureInput =
  | Signature
  | SignatureOptions
  | Uint8Array
  | ReadonlyArray<number>
  | string;
```

## License

[Apache License 2.0](LICENSE.md)
