/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Copyright 2024 University Of Helsinki (The National Library Of Finland)
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this file.
*
*/

import crypto from 'crypto';

import createDebugLogger from 'debug';
import HttpStatus from 'http-status';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import Strategy from 'passport-strategy';

import TokenValidationError from '../utils/tokenValidationError';

/* eslint-disable functional/no-this-expressions */
// NB: requires req.cookies to be set
export default class extends Strategy {
  constructor({algorithms, audience, issuer, jwksUrl, cookieName, cookieEncryptSecretKey, cookieEncryptSecretIV}) {
    super();
    this.name = 'keycloak-jwt-cookie';
    this.cookieName = cookieName;
    this.cookieEncryptSecretKey = cookieEncryptSecretKey;
    this.cookieEncryptSecretIV = cookieEncryptSecretIV;
    this.jwksUrl = jwksUrl;
    this.verifyOpts = {algorithms, audience, issuer, ignoreExpiration: false};

    this._publicKeyCache = {};
  }

  // eslint-disable-next-line max-statements
  async authenticate(req) {
    const debug = createDebugLogger('@natlibfi/passport-keycloak-js/bearer-token:authenticate');

    try {
      const cookie = getCookie(req, this.cookieName);
      if (cookie === null) {
        throw new TokenValidationError('Request did not include authorization cookie');
      }

      const token = decryptCookie(cookie, this.cookieEncryptSecretKey, this.cookieEncryptSecretIV);
      const tokenHeader = getTokenHeader(token);

      const {publicKey, insertCache} = await findPublicKey(tokenHeader, this._publicKeyCache, this.jwksUrl, this.verifyOpts.algorithms);

      if (insertCache) { // eslint-disable-line functional/no-conditional-statements
        this._publicKeyCache[publicKey.kid] = JSON.parse(JSON.stringify(publicKey)); // eslint-disable-line functional/immutable-data
      }

      const publicKeyPem = jwkToPem(publicKey);
      const userInfo = getUserInfo(token, publicKeyPem, this.verifyOpts);

      return this.success(userInfo);
    } catch (err) {
      debug(err);

      if (err instanceof TokenValidationError) { // eslint-disable-line functional/no-conditional-statements
        return this.fail();
      }

      return this.error(err);
    }

    function getCookie(req, cookieName) {
      return req.cookies?.[cookieName] ?? null;
    }

    function getUserInfo(token, publicKey, verifyOpts) {
      let userInfo; // eslint-disable-line functional/no-let

      jwt.verify(token, publicKey, verifyOpts, (err, decoded) => {
        if (err) {
          throw new TokenValidationError(err);
        }

        userInfo = {...decoded};
      });

      return userInfo;
    }

    function getTokenHeader(token) {
      return JSON.parse(atob(token.split('.')[0]));
    }

    /* istanbul ignore next */
    async function findPublicKey(tokenHeader, cache, jwksUrl, validAlgorithms) {
      const keyId = tokenHeader.kid;

      if (!keyId) {
        throw new TokenValidationError('Token did not contain keyId information');
      }

      if (Object.keys(cache).includes(keyId)) {
        return {publicKey: cache[keyId], insertCache: false};
      }

      const response = await fetch(jwksUrl, {
        headers: {Accept: 'application/json'}
      });

      if (response.status !== HttpStatus.OK) {
        throw new TokenValidationError('Could not fetch JWKS information');
      }

      const data = await response.json();
      if (!data.keys || !Array.isArray(data.keys)) {
        throw new TokenValidationError('JWKS response was malformed');
      }

      const result = data.keys.find(key => key.kid === keyId && validAlgorithms.includes(key.alg));
      if (!result) {
        throw new TokenValidationError('JWKS did not contain key appropriate for token');
      }

      return {publicKey: result, insertCache: true};
    }

    // Idea for using crypto KeyObject originally from stack overflow answer comment https://stackoverflow.com/a/75074566
    // Comment by https://stackoverflow.com/users/9014097
    // Example application to TypeScript by https://stackoverflow.com/users/2616445
    function jwkToPem(jwk) {
      const publicKey = crypto.createPublicKey({key: jwk, format: 'jwk'});
      return publicKey.export({format: 'pem', type: 'spki'});
    }

    function decryptCookie(encrypted, secretKey, secretIV) {
      // eslint-disable-next-line no-invalid-this
      const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, secretIV);
      return decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');
    }
  }
}
