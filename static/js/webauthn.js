// Create a private scope
(function() {
  // Various WebAuthn calls require an ArrayBuffer, but Go will serialize
  // []byte arrays as base64 strings. This function converts a base64 string
  // to an ArrayBuffer. The Go WebAuthn library uses base64.RawURLEncoding,
  // so we reverse that so that window.atob can decode it.
  function base64ToUint8Array(base64) {
    // Add padding if necessary
    if (base64.length % 4 === 2) {
      base64 += '==';
    } else if (base64.length % 4 === 3) {
      base64 += '=';
    }

    // Replace URL-safe characters
    base64 = base64
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    // Decode the modified Base64 string
    const binaryString = window.atob(base64);

    // Create a Uint8Array from the binary string
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
  }

  function uint8ArrayToBase64(uint8Array) {
    // Convert Uint8Array to binary string
    let binaryString = '';
    for (let i = 0; i < uint8Array.length; i++) {
      binaryString += String.fromCharCode(uint8Array[i]);
    }

    // Encode binary string to Base64
    let base64 = window.btoa(binaryString);

    // Remove padding characters
    base64 = base64.replace(/=+$/, '');

    // Replace characters to make it URL-safe
    base64 = base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    return base64;
  }

  // Helper error that we raise if we get a non-200 response from the server
  class ResponseError extends Error {
    constructor(message, res) {
      super(message);
      this.response = res;
    }
  }

  // translateSessionData modifies the provided 'data', which should be the
  // JSON-deserialized version of the Go *webauthn.SessionData, to a format
  // that the browser understands. It modifies 'data' in-place and returns it.
  function translateSessionData(data) {
    // Un-base64 the challenge and user ID
    data.publicKey.challenge = base64ToUint8Array(data.publicKey.challenge);

    if (data.publicKey.user && data.publicKey.user.id) {
      data.publicKey.user.id = base64ToUint8Array(data.publicKey.user.id);
    }

    if (data.publicKey.allowCredentials) {
        data.publicKey.allowCredentials.forEach((c) => {
          c.id = base64ToUint8Array(c.id);
        });
    }
    return data;
  }

  function doRegister() {
    // Call the register endpoint to get the credential options
    const prom = fetch('/account/webauthn/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        //email: '{{ .User.Email }}'
      })
    });
    
    return prom
      .then((r) => {
        if(r.status !== 200) {
          throw new ResponseError("failed to get credential options", r);
        }
        return r.json();
      })
      .then((data) => {
        data = translateSessionData(data);

        // Call the navigator.credentials.create method to create a new credential
        console.log("calling navigator.credentials.create with:", data);
        return navigator.credentials.create(data);
      })
      .then((cred) => {
        console.log("got credential:", cred);

        // The Go WebAuthn library expcts the following fields as base64 strings:
        // - rawId
        // - response.attestationObject
        // - response.authenticatorData
        // - response.clientDataJSON
        // - response.publicKey
        //
        // Create a new type that mirrors PublicKeyCredential and contains
        // the base64'd versions of these fields.
        const newCred = {
          authenticatorAttachment: cred.authenticatorAttachment,
          id: cred.id,
          rawId: uint8ArrayToBase64(new Uint8Array(cred.rawId)),

          // 'response' is of type AuthenticatorAttestationResponse, since per MDN:
          //
          //    It is either of type AuthenticatorAttestationResponse if the
          //    PublicKeyCredential was the results of a navigator.credentials.create()
          //    call, or of type AuthenticatorAssertionResponse if the
          //    PublicKeyCredential was the result of a navigator.credentials.get() call
          response: {
            attestationObject: uint8ArrayToBase64(new Uint8Array(cred.response.attestationObject)),
            //authenticatorData: uint8ArrayToBase64(new Uint8Array(cred.response.authenticatorData)),
            clientDataJSON: uint8ArrayToBase64(new Uint8Array(cred.response.clientDataJSON)),
            //publicKey: uint8ArrayToBase64(new Uint8Array(cred.response.publicKey)),
          },

          type: cred.type,
        };

        debugger;

        // Send the credential to the server
        return fetch('/account/webauthn/register-complete', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(newCred),
        })
      })
      .then((r) => {
        if(r.status !== 200) {
          throw new ResponseError("failed to register credential", r);
        }
        return r.json();
      })
      .then((data) => {
        console.log("got register response:", data);
      })
      .catch((err) => {
        console.error("error:", err);

        // Re-throw the error so that it can be caught by the caller
        throw err;
      });
  }

  function doLogin(username) {
    // Call the register endpoint to get the credential options
    const prom = fetch('/login/webauthn', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: username,
      }),
    });

    return prom
      .then((r) => {
        if(r.status !== 200) {
          throw new ResponseError("failed to get credential options", r);
        }
        return r.json();
      })
      .then((data) => {
        // Un-base64 the challenge and user ID
        data = translateSessionData(data);

        // Call the navigator.credentials.get method to begin logging in.
        console.log("calling navigator.credentials.get with:", data);
        return navigator.credentials.get(data);
      })
      .then((cred) => {
        console.log("got credential:", cred);

        // 'response' is of type AuthenticatorAssertionResponse, since per MDN:
        //
        //    It is either of type AuthenticatorAttestationResponse if the
        //    PublicKeyCredential was the results of a navigator.credentials.create()
        //    call, or of type AuthenticatorAssertionResponse if the
        //    PublicKeyCredential was the result of a navigator.credentials.get() call
        const newCred = {
          authenticatorAttachment: cred.authenticatorAttachment,
          id: cred.id,
          rawId: uint8ArrayToBase64(new Uint8Array(cred.rawId)),
          response: {
            authenticatorData: uint8ArrayToBase64(new Uint8Array(cred.response.authenticatorData)),
            clientDataJSON: uint8ArrayToBase64(new Uint8Array(cred.response.clientDataJSON)),
            signature: uint8ArrayToBase64(new Uint8Array(cred.response.signature)),
            userHandle: uint8ArrayToBase64(new Uint8Array(cred.response.userHandle)),
          },
          type: cred.type,
        };

        // Resolve the promise with the credential, so that the caller can
        // transmit it to the server in an appropriate method.
        return newCred;
      })
      .catch((err) => {
        console.error("error:", err);

        // Re-throw the error so that it can be caught by the caller
        throw err;
      });
  }

  // Export just the functions we want to a top-level object.
  window.homeauth = {
      doRegister: doRegister,
      doLogin: doLogin,
  };
})();
