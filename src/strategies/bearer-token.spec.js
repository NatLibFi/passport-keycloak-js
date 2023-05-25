/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Copyright 2023 University Of Helsinki (The National Library Of Finland)
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

/* eslint-disable functional/immutable-data */

import chai, {expect} from 'chai';
import chaiPassportStrategy from 'chai-passport-strategy';
import {generateKeyPairSync} from 'crypto';
import jwt from 'jsonwebtoken';

import Strategy from './bearer-token';

chai.use(chaiPassportStrategy);

const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'pem'}});
const signOpts = {algorithm: 'RS256'};

describe('strategies/bearer-token', () => {
  it('Should call success() when token is valid', () => {
    const payload = {
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .fail(() => reject(new Error('Should not call fail()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .success(user => {
          try {
            expect(user).to.eql(payload);
            resolve();
          } catch (err) {
            reject(err);
          }
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Should call fail() because of invalid token', () => {
    const {privateKey: anotherPrivateKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'pem'}});

    const payload = {
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, anotherPrivateKey, signOpts);

    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(resolve)
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Should call fail() when token audience is not valid', () => {
    const payload = {
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'not.valid.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(resolve)
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Should call fail() when token issuer is not valid', () => {
    const payload = {
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'not.valid.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(resolve)
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });


  it('Should call fail() because of missing token', () => {
    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(resolve)
        .authenticate();
    });
  });

  it('Should call fail() because of expired token', () => {
    const payload = {
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) - 50
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      publicKey,
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(resolve)
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });
});
