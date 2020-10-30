# @lindorm-io/key-pair
This package contains Key Pair functionality for lindorm.io packages.

## Installation
```shell script
npm install --save @lindorm-io/key-pair
```

### Peer Dependencies
This package has the following peer dependencies: 
* [@lindorm-io/common](https://www.npmjs.com/package/@lindorm-io/common)
* [@lindorm-io/global](https://www.npmjs.com/package/@lindorm-io/global)

## Usage

### KeyPair
```typescript
const eccData = await generateECCKeys();
const eccKeyPair = new KeyPair(eccData);
eccKeyPair.create();
eccKeyPair.expire();

const rsaData = await generateRSAKeys();
const rsaKeyPair = new KeyPair(rsaData);
rsaKeyPair.create();
```

### Keystore
```typescript
const keystore = new KeyStore({ keys: [eccKeyPair, rsaKeyPair] });

keystore.getCurrentKey(); // -> rsaKeyPair entity
keystore.getKey(eccKeyPair.id); // -> eccKeyPair entity
```

### KeyPairHandler
```typescript
const handler = new KeyPairHandler({
  algorithm: rsaKeyPair.algorithm,
  privateKey: rsaKeyPair.privateKey,
  publicKey: rsaKeyPair.publicKey,
});
const signature = handler.sign("input");

const verify = handler.verify("input", signature);
handler.assert("input", signature);

const privateSignature = handler.encrypt(SignMethod.PRIVATE_SIGN, "input");
const publicDecrypt = handler.decrypt(SignMethod.PRIVATE_SIGN, privateSignature);

const publicSignature = handler.encrypt(SignMethod.PUBLIC_SIGN, "input");
const privateDecrypt = handler.decrypt(SignMethod.PUBLIC_SIGN, publicSignature);
```
