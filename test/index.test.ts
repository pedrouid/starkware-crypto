import * as starkwareCrypto from '../src';

// ---------------------- TEST DATA POINTS ---------------------- //

const mnemonic =
  'puzzle number lab sense puzzle escape glove faith strike poem acoustic picture grit struggle know tuna soul indoor thumb dune fit job timber motor';
const layer = 'starkex';
const application = 'starkexdvf';
const zeroAddress = '0x0000000000000000000000000000000000000000';
const index = '0';

// ---------------------- EXPECTED DATA POINTS ---------------------- //

const STARK_DERIVATION_PATH = `m/2645'/579218131'/1393043894'/0'/0'/0`;
const PUBLIC_KEY =
  '04042582cfcb098a503562acd1325922799c9cebdf9249c26a41bd04007997f2eb03b73cdb07f399130ea38ee860c3b708c92165df37b1690d7e0af1678ecdaff8';
const PUBLIC_KEY_COMPRESSED =
  '02042582cfcb098a503562acd1325922799c9cebdf9249c26a41bd04007997f2eb';
const STARK_PUBLIC_KEY =
  '0x042582cfcb098a503562acd1325922799c9cebdf9249c26a41bd04007997f2eb';
const STARK_SIGNATURE =
  '0x7130036cfee14ee468f84538da0b2c71f11908f3dcc4c0b7fb28c2e0c8504d1e4e3191d2adb180a2ec31eff2366381e2ec807426f232a6cae2387d6d7886e1c';

describe('starkware-crypto', () => {
  let path: string;
  let keyPair: starkwareCrypto.KeyPair;
  beforeEach(() => {
    path = starkwareCrypto.getAccountPath(
      layer,
      application,
      zeroAddress,
      index
    );
    keyPair = starkwareCrypto.getKeyPairFromPath(mnemonic, path);
  });

  it('should match expected derivation path', () => {
    expect(path).toEqual(STARK_DERIVATION_PATH);
  });

  it('should match expected public key', () => {
    const publicKey = starkwareCrypto.getPublic(keyPair);
    expect(publicKey).toEqual(PUBLIC_KEY);
  });

  it('should match expected public key compressed', () => {
    const publicKey = starkwareCrypto.getPublic(keyPair, true);
    expect(publicKey).toEqual(PUBLIC_KEY_COMPRESSED);
  });

  it('should generate starkPublicKey', () => {
    const publicKey = starkwareCrypto.getPublic(keyPair);
    const starkPublicKey = starkwareCrypto.getStarkPublicKey(publicKey);
    expect(starkPublicKey).toEqual(STARK_PUBLIC_KEY);
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

    expect(starkwareCrypto.serializeSignature(signature)).toEqual(
      STARK_SIGNATURE
    );

    const verified = starkwareCrypto.verify(keyPair, message, signature);

    expect(verified).toBeTruthy();
  });
});
