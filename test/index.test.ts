import * as starkwareCrypto from '../src';

const privateKey =
  '0x659d82c1cc4c3e6fead938999322116a3dc7854b415b822dbea42630ecd90b5e';

describe('starkware-crypto', () => {
  let keyPair: starkwareCrypto.KeyPair;
  beforeEach(() => {
    keyPair = starkwareCrypto.getKeyPair(privateKey);
  });

  it('should generate starkKey', () => {
    const publicKey = starkwareCrypto.getPublic(keyPair);

    const starkKey = starkwareCrypto.getStarkKey(publicKey);

    expect(starkKey).toBeTruthy();
  });

  it('should generate and sign transfer message', () => {
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

    expect(verified).toBeTruthy();
  });
});
