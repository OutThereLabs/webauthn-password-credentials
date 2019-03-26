import {KJUR,KEYUTIL} from 'jsrsasign';
import {BigInteger} from 'bignumber';

function bufferFromBas64String(base64String: string): ArrayBuffer {
  var len = base64String.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = base64String.charCodeAt(i);
  }
  return bytes.buffer
}

function deriveJWK(credential: PasswordCredential, domain: string): object {
  // HMAC user:pass with domain to get private key
  var ecparams = KJUR.crypto.ECParameterDB.getByName("secp256r1");
  var privateKeyDeriver = new KJUR.crypto.Mac({ "alg": "HmacSHA512", "prov": "cryptojs", "pass": domain });
  privateKeyDeriver.updateString(credential.id + ":" + credential.password);
  var privateKeyWithID = privateKeyDeriver.doFinal();

  var keyID = privateKeyWithID.substring(64);

  var biPrv = new BigInteger(privateKeyWithID.substring(0, 64), "16");

  // Dervice public key
  var epPub = ecparams['G'].multiply(biPrv);
  var biX = epPub.getX().toBigInteger();
  var biY = epPub.getY().toBigInteger();

  // Create KJUR key
  var charlen = ecparams['keylen'] / 4;
  var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
  var hX = ("0000000000" + biX.toString(16)).slice(- charlen);
  var hY = ("0000000000" + biY.toString(16)).slice(- charlen);
  var hPub = "04" + hX + hY;
  var key = new KJUR.crypto.ECDSA()
  key.setPrivateKeyHex(hPrv);
  key.setPublicKeyHex(hPub);

  // Return JWK
  var jwk = KEYUTIL.getJWKFromKey(key);
  jwk["ext"] = true;
  jwk["key_ops"] = ["sign"];
  jwk["kid"] = keyID;
  return jwk;
}

export class JWKCryptoKey {
  id: string;
  key: CryptoKey;

  constructor(id: string, key: CryptoKey) {
    this.id = id;
    this.key = key;
  }

  static from(credential: PasswordCredential, domain: string): PromiseLike<JWKCryptoKey> {
    const jwk = deriveJWK(credential, domain);
    
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["sign"]
    ).then((key) => {
      return new JWKCryptoKey(jwk['kid'], key);
    });
  }
}