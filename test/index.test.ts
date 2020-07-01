import * as bip39 from 'bip39';
import hdkey from 'ethereumjs-wallet/hdkey';

import * as starkwareCrypto from '../src';

const mnemonic =
  'puzzle number lab sense puzzle escape glove faith strike poem acoustic picture grit struggle know tuna soul indoor thumb dune fit job timber motor';

const layer = 'starkex';
const application = 'starkexdvf';

const ethDerivationPath = `m/44'/60'/0'/0'/0`;
const ethWallet = hdkey
  .fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic))
  .derivePath(ethDerivationPath)
  .getWallet();
const ethAddress = ethWallet.getAddressString();
console.log(ethAddress);

const starkDerivationPath = `m/2645'/579218131'/1393043894'/1007594250'/1485436526'/0`;

describe('starkware-crypto', () => {
  let keyPair: starkwareCrypto.KeyPair;
  beforeEach(() => {
    keyPair = starkwareCrypto.getKeyPairFromPath(mnemonic, starkDerivationPath);
  });

  it('should generate path from params', () => {
    const path = starkwareCrypto.getAccountPath(
      layer,
      application,
      ethAddress,
      '0'
    );
    expect(path).toEqual(starkDerivationPath);
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
