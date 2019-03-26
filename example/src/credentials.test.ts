import { credentials } from 'webauthn-credentials';
import * as chai from 'chai';

describe('Credentials', () => {
  it('should get a valid response when getting credentials' , () => {
    let credential = new PasswordCredential({
      id: "my-username",
      password: "my-password",
    });

    let options = {
      challenge: new Uint8Array([0, 1, 2, 3]),
      extensions: {
        passwordCredential: credential,
        domain: "example.com"
      }
    };

    return credentials.get({"publicKey": options}).then((response) => {
      chai.expect(response.id).to.equal("8c4752ffceabd86e407945dc80f8c1845db128cc7226d5517be71e4623a385d3");
    })
  });
});
