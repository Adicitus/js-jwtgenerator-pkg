# js-jwtgenerator-pkg
NPM package to easily generate/verify JWT using public key cryptography.

## Usage
Install with npm:
`npm install @adicitus/jwtgenerator`

The module exports the class JWTGenerator, which can be used to generate JSON web tokens:
```
const JWTGenerator = require('@adicitus/jwtgenerator')
const generator = new JWTGenerator()
```

The generator instance can then be used to generate tokens:
```
let {token, record} = generator.newToken('subject')
```

And can then be used to verify the validity of the token:
```
Let result = generator.verifyToken(token, {record: record})
```

The record contains information needed to validate the token, and should be stored by the caller.
