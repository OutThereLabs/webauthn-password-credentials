import { JWKCryptoKey } from 'webauthn-credentials';
import * as chai from 'chai';

describe('Keypair Generator', () => {
  it('should be able to generate a keypair from a username/password' , () => {
    let credential = new PasswordCredential({
      id: "my-username",
      password: "my-password",
    });
    
    return JWKCryptoKey.from(credential, "example.com").then(jwk => {
      return crypto.subtle.exportKey("jwk", jwk.key);
    }).then((jwk) => {
      chai.expect(jwk["d"]).to.equal("8JuU_DoNBHE_KvA86OpaeJQwTI1Xkr2RVASFfEIq61s");
    });
  });
});
