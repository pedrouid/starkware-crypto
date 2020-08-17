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
const STARK_SIGNATURE_ERC20 =
  '0x001cea14438f3715ba87d06978e6633f1e6a13e6b62f3b2be05af8c268c76e1a03f12e766d9ff9bd622b36c50f4c6b64b494cfc6e7117c29bce06787b2cf3e551b';
const STARK_SIGNATURE_ETH =
  '0x01df4e7bbad23da5e5266c2d724b5c892c9cc25cdb8a5c3371bac53013f3d5270715136cb5e9bf1f2733885d98cebded918e80f130ec85506e2779d364dd83a81c';

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

  it('match expected derivation path', () => {
    expect(path).toEqual(STARK_DERIVATION_PATH);
  });

  it('match expected public key', () => {
    const publicKey = starkwareCrypto.getPublic(keyPair);
    expect(publicKey).toEqual(PUBLIC_KEY);
  });

  it('match expected public key compressed', () => {
    const compressed = starkwareCrypto.getPublic(keyPair, true);
    expect(compressed).toEqual(PUBLIC_KEY_COMPRESSED);
  });

  it('compress', () => {
    const compressed = starkwareCrypto.compress(PUBLIC_KEY);
    expect(compressed).toEqual(PUBLIC_KEY_COMPRESSED);
  });

  it('decompress', () => {
    const publicKey = starkwareCrypto.decompress(PUBLIC_KEY_COMPRESSED);
    expect(publicKey).toEqual(PUBLIC_KEY);
  });

  it('sign eth transfer message', () => {
    const params = {
      from: {
        starkPublicKey:
          '0x03a535c13f12c6a2c7e7c0dade3a68225988698687e396a321c12f5d393bea4a',
        vaultId: '1',
      },
      to: {
        starkPublicKey:
          '0x03a535c13f12c6a2c7e7c0dade3a68225988698687e396a321c12f5d393bea4a',
        vaultId: '606138218',
      },
      token: { type: 'ETH' as 'ETH', data: { quantum: '10000000000' } },
      quantizedAmount: '100000000',
      nonce: '1597237097',
      expirationTimestamp: '444396',
    };

    const message = starkwareCrypto.getTransferMsg(
      params.quantizedAmount,
      params.nonce,
      params.from.vaultId,
      params.token,
      params.to.vaultId,
      params.to.starkPublicKey,
      params.expirationTimestamp
    );

    const signature = starkwareCrypto.sign(keyPair, message);

    expect(starkwareCrypto.serializeSignature(signature)).toEqual(
      STARK_SIGNATURE_ETH
    );

    const verified = starkwareCrypto.verify(keyPair, message, signature);

    expect(verified).toBeTruthy();
  });

  it('sign erc20 transfer message', () => {
    const params = {
      from: {
        vaultId: '34',
        starkPublicKey:
          '0x5fa3383597691ea9d827a79e1a4f0f7949435ced18ca9619de8ab97e661020',
      },
      to: {
        vaultId: '21',
        starkPublicKey:
          '0x5fa3383597691ea9d827a79e1a4f0f7949435ced18ca9619de8ab97e661020',
      },
      token: {
        type: 'ERC20' as 'ERC20',
        data: {
          quantum: '1',
          tokenAddress: '0x89b94e8C299235c00F97E6B0D7368E82d640E848',
        },
      },
      quantizedAmount: '2154549703648910716',
      nonce: '1',
      expirationTimestamp: '438953',
    };

    const message = starkwareCrypto.getTransferMsg(
      params.quantizedAmount,
      params.nonce,
      params.from.vaultId,
      params.token,
      params.to.vaultId,
      params.to.starkPublicKey,
      params.expirationTimestamp
    );

    const signature = starkwareCrypto.sign(keyPair, message);

    expect(starkwareCrypto.serializeSignature(signature)).toEqual(
      STARK_SIGNATURE_ERC20
    );

    const verified = starkwareCrypto.verify(keyPair, message, signature);

    expect(verified).toBeTruthy();
  });
});
