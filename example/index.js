/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

var Keycloak = require('keycloak-connect');
var Koa = require('koa');
const render = require('koa-ejs');
var session = require('koa-session');
var Router = require('koa-router');
const path = require('path');

var app = new Koa();
var router = new Router();

// Create a session-store to be used by both the express-session
// middleware and the keycloak middleware.

var MemoryStore = require('./util/memory-store');
var store = new MemoryStore();
app.use(session({
  key: 'koa:sess',
  maxAge: 86400000,
  renew: false,
  store: store,
  signed: false
}, app));

// ejs template engine
render(app, {
  root: path.join(__dirname, 'view'),
  layout: 'index',
  viewExt: 'html',
  cache: false,
  debug: true
});

// Provide the session store to the Keycloak so that sessions
// can be invalidated from the Keycloak console callback.
//
// Additional configuration is read from keycloak.json file
// installed from the Keycloak web console.

var keycloak = new Keycloak({
  store: true
}, {
  clientId: 'photoz-html5-client',
  serverUrl: 'http://auth.sunmaoyun.io/auth',
  realm: 'photoz',
  bearerOnly: false
});

// Install the Keycloak middleware.
//
// Specifies that the user-accessible application URL to
// logout should be mounted at /logout
//
// Specifies that Keycloak console callbacks should target the
// root URL.  Various permutations, such as /k_logout will ultimately
// be appended to the admin URL.

var middlewares = keycloak.middleware({
  logout: '/logout',
  admin: '/',
  protected: '/protected/resource'
});
middlewares.forEach(function (middleware) {
  app.use(middleware);
});

router.get('/', async (ctx) => {
  await ctx.render('index', {
    data: {
      result: '',
      event: ''
    }
  });
});

router.get('/login', keycloak.protect(), async function (ctx) {
  await ctx.render('index', {
    data: {
      result: JSON.stringify(JSON.parse(ctx.session['keycloak-token']), null, 4),
      event: '1. Authentication\n2. Login'
    }
  });
});

router.get('/protected/resource', keycloak.enforcer(['resource:view', 'resource:write'], {
  resource_server_id: 'nodejs-apiserver'
}), async function (ctx) {
  await ctx.render('index', {
    data: {
      result: JSON.stringify(JSON.parse(ctx.session['keycloak-token']), null, 4),
      event: '1. Access granted to Default Resource\n'
    }
  });
});

app.use(router.routes()).use(router.allowedMethods());

app.listen(8081);
