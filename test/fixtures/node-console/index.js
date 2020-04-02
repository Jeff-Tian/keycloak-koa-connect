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
'use strict';

const Keycloak = require('../../../');
const Koa = require('koa');
const bodyParser = require('body-parser');
const session = require('koa-session');
const parseClient = require('../../utils/helper').parseClient;
const Router = require('koa-router');
const enableDestroy = require('server-destroy');
const render = require('koa-ejs');

Keycloak.prototype.redirectToLogin = function (req) {
  var apiMatcher = /^\/service\/.*/i;
  return !apiMatcher.test(req.baseUrl);
};

Keycloak.prototype.obtainDirectly = function (user, pass) {
  return this.grantManager.obtainDirectly(user, pass);
};

function NodeApp () {
  var app = new Koa();
  const router = new Router();

  this.publicClient = function (app) {
    const name = app || 'public-app';
    return parseClient('test/fixtures/templates/public-template.json', this.port, name);
  };

  this.bearerOnly = function (app) {
    var name = app || 'bearer-app';
    return parseClient('test/fixtures/templates/bearerOnly-template.json', this.port, name);
  };

  this.confidential = function (app) {
    var name = app || 'confidential-app';
    return parseClient('test/fixtures/templates/confidential-template.json', this.port, name);
  };

  this.enforcerResourceServer = function (app) {
    var name = app || 'resource-server-app';
    return parseClient('test/fixtures/templates/resource-server-template.json', this.port, name);
  };

  this.build = function (kcConfig, params) {
    render(app, {
      root: require('path').join(__dirname, '/views'),
      layout: false,
      viewExt: 'html',
      cache: false,
      debug: true
    });

    // Create a session-store to be used by both the express-session
    // middleware and the keycloak middleware.

    var MemoryStore = require('../../../example/util/memory-store');
    var store = new MemoryStore();

    app.use(session({
      secret: 'mySecret',
      resave: false,
      renew: false,
      saveUninitialized: true,
      store: store
    }, app));

    // Provide the session store to the Keycloak so that sessions
    // can be invalidated from the Keycloak console callback.
    //
    // Additional configuration is read from keycloak.json file
    // installed from the Keycloak web console.
    params = params || { store: MemoryStore };
    var keycloak = new Keycloak(params, kcConfig);

    router.get('/health-check', async ctx =>
      ctx.render('index', {result: {}, event:{}})
    );

    // A normal un-protected public URL.
    router.get('/', function (ctx) {
      const authenticated = 'Init Success (' + (ctx.session['keycloak-token'] ?
          'Authenticated' :
          'Not Authenticated') + ')';
      console.log('auth info = ', authenticated);
      return output(ctx, authenticated);
    });

    // Install the Keycloak middleware.
    //
    // Specifies that the user-accessible application URL to
    // logout should be mounted at /logout
    //
    // Specifies that Keycloak console callbacks should target the
    // root URL.  Various permutations, such as /k_logout will ultimately
    // be appended to the admin URL.

    const middlewares = keycloak.middleware({
      logout: '/logout',
      admin: '/'
    });

    middlewares.forEach(function(middleware){
      app.use(middleware);
    });

    router.get('/login', keycloak.protect(), function (ctx) {
      const { res } = ctx;
      return output(ctx, JSON.stringify(JSON.parse(ctx.session['keycloak-token']), null, 4), 'Auth Success');
    });

    router.get('/check-sso', keycloak.checkSso(), function (ctx) {
      const { res } = ctx;
      var authenticated = 'Check SSO Success (' + (ctx.session['keycloak-token'] ? 'Authenticated' : 'Not Authenticated') + ')';
      return output(ctx, authenticated);
    });

    router.get('/restricted', keycloak.protect('realm:admin'), function (ctx) {
      const { req, res } = ctx;
      var user = req.kauth.grant.access_token.content.preferred_username;
      return output(ctx, user, 'Restricted access');
    });

    router.get('/service/public', function (ctx) {
      const { res } = ctx;
      res.json({ message: 'public' });
    });

    router.get('/service/secured', keycloak.protect('realm:user'), function (ctx) {
      const { res } = ctx;
      res.json({ message: 'secured' });
    });

    router.get('/service/admin', keycloak.protect('realm:admin'), function (ctx) {
      const { res } = ctx;
      res.json({ message: 'admin' });
    });

    router.get('/service/grant', keycloak.protect(), (ctx, next) => {
      const { req, res } = ctx;
      keycloak.getGrant(req, res)
        .then(grant => {
          res.json(grant);
        })
        .catch(next);
    });

    router.post('/service/grant', bodyParser.json(), (ctx, next) => {
      const { req, res } = ctx;
      if (!req.body.username || !req.body.password) {
        res.status(400).send('Username and password required');
      }
      keycloak.obtainDirectly(req.body.username, req.body.password)
        .then(grant => {
          keycloak.storeGrant(grant, req, res);
          res.json(grant);
        })
        .catch(next);
    });

    router.get('/protected/enforcer/resource', keycloak.enforcer('resource:view'), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: 'resource:view', permissions: req.permissions });
    });

    router.post('/protected/enforcer/resource', keycloak.enforcer('resource:update'), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: 'resource:update', permissions: req.permissions });
    });

    router.delete('/protected/enforcer/resource', keycloak.enforcer('resource:delete'), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: 'resource:delete', permissions: req.permissions });
    });

    router.get('/protected/enforcer/resource-view-delete', keycloak.enforcer(['resource:view', 'resource:delete']), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: 'resource:delete', permissions: req.permissions });
    });

    router.get('/protected/enforcer/resource-claims', keycloak.enforcer(['photo'], {
      claims: function (request) {
        return {
          user_agent: [request.query.user_agent]
        };
      }
    }), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: req.query.user_agent, permissions: req.permissions });
    });

    router.get('/protected/enforcer/no-permission-defined', keycloak.enforcer(), function (ctx) {
      const { req, res } = ctx;
      res.json({ message: 'always grant', permissions: req.permissions });
    });

    router.get('/protected/web/resource', keycloak.enforcer(['resource:view']), function (ctx) {
      const { req} = ctx;
      var user = req.kauth.grant.access_token.content.preferred_username;
      return output(ctx, user, 'Granted');
    });

    router.use('*', function (ctx) {
      console.log('404 reached');
      const { res } = ctx;
      res.send('Not found!');
    });

    app.use(router.routes()).use(router.allowedMethods());
  };

  var server = app.listen(0);
  enableDestroy(server);
  this.close = function () {
    server.close();
  };
  this.destroy = function () {
    server.destroy();
  };
  this.port = server.address().port;
  this.address = 'http://127.0.0.1:' + this.port;

  console.log('Testing app listening at http://localhost:%s', this.port);
}

function output (ctx, output, eventMessage, page) {
  page = page || 'index';
  console.log('rendering ...', page);
  return ctx.render(page, {
    result: output,
    event: eventMessage
  });
}

module.exports = {
  NodeApp: NodeApp
};
