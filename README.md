# starkware-crypto [![npm version](https://badge.fury.io/js/starkware-crypto.svg)](https://badge.fury.io/js/starkware-crypto)

Starkware Crypto Library

## Description

This library is a port from [starkex-resources/\*\*/signature.js](https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature.js).

## Example

```typescript
import * as starkwareCrypto from 'starkware-crypto';

const privateKey =
  '0x659d82c1cc4c3e6fead938999322116a3dc7854b415b822dbea42630ecd90b5e';

const keyPair = starkwareCrypto.getKeyPair(privateKey);

const publicKey = starkwareCrypto.getPublic(privateKey);

const starkKey = starkwareCrypto.getStarkKey(publicKey);

const message = starkwareCrypto.getTransferMsg(...params);

const signature = starkwareCrypto.sign(keyPair, message);

const verified = starkwareCrypto.verify(keyPair, message, signature);
```

### API

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

interface StarkwareCrypto {
  getKeyPair(privateKey: string): KeyPair;

  getStarkKey(publicKey: string);

  getPrivate(keyPair: KeyPair): string;

  getPublic(keyPair: KeyPair): string;

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
    instruction: 'transfer' | 'trade',
    vault0: string,
    vault1: string,
    amount0: string,
    amount1: string,
    token0: string,
    token1: string,
    nonce: string,
    expirationTimestamp: string
  ): string;

  getLimitOrderMsg(
    vaultSell: string,
    vaultBuy: string,
    amountSell: string,
    amountBuy: string,
    tokenSell: string,
    tokenBuy: string,
    nonce: string,
    expirationTimestamp: string
  ): string;

  getTransferMsg(
    amount: string,
    nonce: string,
    senderVaultId: string,
    token: string,
    receiverVaultId: string,
    receiverPublicKey: string,
    expirationTimestamp: string
  ): string;

  sign(keyPair: KeyPair, msg: string): elliptic.ec.Signature;

  verify(
    keyPair: KeyPair,
    msg: string,
    msgSignature: elliptic.SignatureInput
  ): boolean;
}
```

## License

[Apache License 2.0](LICENSE.md)
