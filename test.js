'use strict';

const NodeApp = require('./test/fixtures/node-console/index.js').NodeApp;

const app = new NodeApp();
app.build({
    realm: 'policy-enforcer-realm',
    'auth-server-url': 'http://127.0.0.1:8080/auth',
    'ssl-required': 'external',
    resource: 'resource-server-app',
    'verify-token-audience': true,
    credentials: { secret: '5b5120a0-5e41-4cdd-af8a-72c470db0b59' },
    'confidential-port': 0,
    'policy-enforcer': {}
});

console.log('built');