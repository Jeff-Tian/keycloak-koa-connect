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

const UUID = require('./../uuid');
const URL = require('url');

function forceCheckSSO (keycloak, ctx) {
  const { request, response } = ctx;
  const host = request.hostname;
  const headerHost = request.headers.host.split(':');
  const port = headerHost[1] || '';
  const protocol = request.protocol;
  let hasQuery = ~(request.originalUrl || request.url).indexOf('?');

  const redirectUrl = protocol + '://' + host + (port === '' ? '' : ':' + port) + (request.originalUrl || request.url) + (hasQuery ? '&' : '?') + 'auth_callback=1';

  if (ctx.session) {
    ctx.session.auth_redirect_uri = redirectUrl;
  }

  const uuid = UUID();
  const loginURL = keycloak.loginUrl(uuid, redirectUrl);
  const checkSsoUrl = loginURL + '&response_mode=query&prompt=none';

  response.redirect(checkSsoUrl);
}

module.exports = function (keycloak) {
  return async function checkSso (ctx, next) {
    const { request, response } = ctx;
    if (request.kauth && request.kauth.grant) {
      await next();
      return;
    }

    //  Check SSO process is completed and user is not logged in
    if (ctx.session.auth_is_check_sso_complete) {
      ctx.session.auth_is_check_sso_complete = false;
      await next();
      return;
    }

    //  Keycloak server has just answered that user is not logged in
    if (request.query.error === 'login_required') {
      let urlParts = {
        pathname: request.path,
        query: request.query
      };

      delete urlParts.query.error;
      delete urlParts.query.auth_callback;
      delete urlParts.query.state;

      let cleanUrl = URL.format(urlParts);

      //  Check SSO process is completed
      ctx.session.auth_is_check_sso_complete = true;

      //  Redirect back to the original URL
      return response.redirect(cleanUrl);
    }

    if (keycloak.redirectToLogin(request)) {
      forceCheckSSO(keycloak, ctx);
    } else {
      return keycloak.accessDenied(ctx, next);
    }
  };
};
