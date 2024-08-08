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

/* eslint-disable functional/immutable-data, max-lines */

import chai, {expect} from 'chai';
import chaiPassportStrategy from 'chai-passport-strategy';
import {generateKeyPairSync} from 'crypto';
import nock from 'nock';
import jwt from 'jsonwebtoken';

import Strategy from './bearer-token';

chai.use(chaiPassportStrategy);

const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'jwk'}});
const signOpts = {algorithm: 'RS256', header: {kid: 'foo.keyid'}};

describe('strategies/bearer-token', () => {
  afterEach(() => nock.cleanAll());

  it('Should call success() when token is valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
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
            expect(scope.isDone()).to.eql(true);
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
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const {privateKey: anotherPrivateKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'jwk'}});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, anotherPrivateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Should call fail() when token audience is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'not.valid.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Should call fail() when token issuer is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'not.valid.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });


  it('Should call fail() because of missing token. JWKS endpoint was not queried.', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          const interceptor = scope.interceptors.find(i => i.uri === '/realms/foo/protocol/openid-connect/certs');
          expect(interceptor).to.haveOwnProperty('interceptionCounter');
          expect(interceptor.interceptionCounter).to.eql(0);
          resolve();
        })
        .authenticate();
    });
  });

  it('Should call fail() because of expired token', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) - 50
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: calls success when both tokens are valid()', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const userPayload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(userPayload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .fail(() => reject(new Error('Should not call fail()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .success(user => {
          try {
            expect(user.user).to.eql(userPayload);
            expect(user.service).to.eql(servicePayload);
            expect(scope.isDone()).to.eql(true);
            resolve();
          } catch (err) {
            reject(err);
          }
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: calls fail() when service token is invalid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const {privateKey: anotherPrivateKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'jwk'}});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, anotherPrivateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: calls fail() when user token is invalid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const {privateKey: anotherPrivateKey} = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type: 'spki', format: 'jwk'}});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, anotherPrivateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: should call fail() when service token audience is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'not.valid.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: should call fail() when user token audience is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'not.valid.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: should call fail() when service token issuer is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'not.valid.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: should call fail() when user token issuer is not valid', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'not.valid.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: Should call fail() because of missing service token. Does not make call to JWKS endpoint.', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          const interceptor = scope.interceptors.find(i => i.uri === '/realms/foo/protocol/openid-connect/certs');
          expect(interceptor).to.haveOwnProperty('interceptionCounter');
          expect(interceptor.interceptionCounter).to.eql(0);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: Should call fail() because of missing user token. Does not make call to JWKS endpoint.', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          const interceptor = scope.interceptors.find(i => i.uri === '/realms/foo/protocol/openid-connect/certs');
          expect(interceptor).to.haveOwnProperty('interceptionCounter');
          expect(interceptor.interceptionCounter).to.eql(0);
          resolve();
        })
        .request(req => {
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: Should call fail() because of expired service token', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) - 50
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });

  it('Service token option enabled: Should call fail() because of expired user token', () => {
    const scope = nock('http://foobar')
      .get('/realms/foo/protocol/openid-connect/certs')
      .times(1)
      .reply(200, {keys: [{...publicKey, kid: 'foo.keyid', alg: 'RS256'}]});

    const payload = {
      kid: 'foo.keyid',
      id: 'foo.user',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) - 50
    };

    const servicePayload = {
      kid: 'foo.keyid',
      id: 'baz.servicename',
      aud: 'foo.audience',
      iss: 'foo.issuer',
      iat: Math.floor(Date.now() / 1000) + 60
    };

    const token = jwt.sign(payload, privateKey, signOpts);
    const serviceToken = jwt.sign(servicePayload, privateKey, signOpts);

    const strategy = new Strategy({
      jwksUrl: 'http://foobar/realms/foo/protocol/openid-connect/certs',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer',
      serviceAuthHeader: 'customHeader'
    });

    return new Promise((resolve, reject) => {
      chai.passport.use(strategy)
        .success(() => reject(new Error('Should not call success()')))
        .error(err => reject(new Error(`Should not call error(): ${err.stack}`)))
        .fail(() => {
          expect(scope.isDone()).to.eql(true);
          resolve();
        })
        .request(req => {
          req.headers.authorization = `Bearer ${token}`;
          req.headers.customHeader = `Bearer ${serviceToken}`;
        })
        .authenticate();
    });
  });
});
