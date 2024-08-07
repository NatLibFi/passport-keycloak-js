# Passport strategy for Keycloak JWT

Passport strategy for Keycloak JWT. This module has the following features:
- Written in modern day Javascript/ECMAscript
- Supports HTTP Bearer authentication using Keycloak JWT as bearer tokens
- Verifies token locally (i.e. does not use network calls to introspect endpoint, public keys are fetched from jwks endpoint and cached after first use)

## Strategies
This module provides the following Passport strategies.

### Bearer
HTTP Bearer authentication works by using the token generated after signing in to Keycloak for gaining access to the defined resources.

Does **not** allow configuration for ignoring token expiration.

### Usage

#### ES modules
```javascript
import {KeycloakStrategy} from '@natlibfi/passport-keycloak'
```

### Configuration
Configuration of the strategy needs to be passed to the class constructor as object.

- **algorithms (required):** Algorithm for decoding jwt
- **audience (required):** Audience of jwt
- **issuer (required):** Issuer of jwt
- **jwksUrl (required):** JWKS url to fetch public keys from


## License and copyright

Copyright (c) 2023-2024 **University Of Helsinki (The National Library Of Finland)**

This project's source code is licensed under the terms of **MIT license**
