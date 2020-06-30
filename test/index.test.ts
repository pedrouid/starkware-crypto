// import hdkey from 'ethereumjs-wallet/hdkey';

import * as starkwareCrypto from '../src';

// const ethDerivationPath = `m/44'/60'/0'/0'/0`;
// const ethPublicKey = `04beb0169f94d7f4d9b9bdbb67732c3c9c1d13977cc2bb73fc6f6a783e992ae66f169857d3bc9b2e6e02417180a9486a8172268b2e9b33f35c2685875ec4066370`;
// const ethAddress = `0xF1cAbDCa0070727B3c736c62aC44fB373c0eab0a`;
// const ethWallet = hdkey
//   .fromMasterSeed(seedPhrase)
//   .derivePath(ethDerivationPath)
//   .getWallet();
const seedPhrase =
  'puzzle number lab sense puzzle escape glove faith strike poem acoustic picture grit struggle know tuna soul indoor thumb dune fit job timber motor';

const starkDerivationPath = `m/2645'/579218131'/1393043894'/0'/0'/0`;
// const starkPublicKey =
//   '04042582cfcb098a503562acd1325922799c9cebdf9249c26a41bd04007997f2eb03b73cdb07f399130ea38ee860c3b708c92165df37b1690d7e0af1678ecdaff8';

describe('starkware-crypto', () => {
  let keyPair: starkwareCrypto.KeyPair;
  beforeEach(() => {
    keyPair = starkwareCrypto.getKeyPairFromPath(
      seedPhrase,
      starkDerivationPath
    );
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

  // it('should ');
});
