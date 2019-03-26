import { JWKCryptoKey } from './key-pair-generator'

class PasswordDerivedPublicKeyCredentialResponse implements AuthenticatorAssertionResponse {
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer;
  clientDataJSON: ArrayBuffer;

  constructor(userHandle: string, jwk: JWKCryptoKey, challenge: ArrayBuffer, signature: ArrayBuffer) {
    var enc = new TextEncoder();

    this.authenticatorData = enc.encode(btoa(JSON.stringify({})))

    this.signature = signature;

    this.userHandle = enc.encode(userHandle);

    var dec = new TextDecoder();
    this.clientDataJSON = enc.encode(btoa(JSON.stringify({
      challenge: dec.decode(challenge),
      type: "webauthn.get"
    })))
  }
}

class PasswordDerivedPublicKeyCredential implements PublicKeyCredential {
  type: "public-key";
  rawId: ArrayBuffer;
  response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
  id: string;

  constructor(userHandle: string, jwk: JWKCryptoKey, challenge: ArrayBuffer, signature: ArrayBuffer) {
    var enc = new TextEncoder();
    this.id = jwk.id;
    this.rawId = enc.encode(jwk.id);
    this.response = new PasswordDerivedPublicKeyCredentialResponse(userHandle, jwk, challenge, signature);
  }
}

function get(options?: CredentialRequestOptions): PromiseLike<Credential> {
  let passwordCredential: PasswordCredential = options.publicKey.extensions['passwordCredential'];
  let domain: string = options.publicKey.extensions['domain'];
  let userHandle = passwordCredential.id + "@" + domain;
  let challenge = <ArrayBuffer>options.publicKey.challenge;

  return JWKCryptoKey.from(passwordCredential, domain).then((jwk) => {
    return window.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: {
          name: "SHA-256"
        },
      },
      jwk.key,
      challenge
    ).then((signature) => {
      return new PasswordDerivedPublicKeyCredential(userHandle, jwk, challenge, signature);
    });
  });
}

export const credentials = {
  get: get
}
