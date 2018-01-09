// @flow

// Example implementation of OAuth flow, as used in Echo

import {app} from '../app'
import {log} from '../log'
import url from 'url'
import crypto from 'crypto'
import request from 'request-promise'

// Config:

// config.secret.client_secret
// config.secret.client_id

// config.OAuth_url         Oauth page address, including "?response_type=code&"
// config.callback_url      Backend callback for , defined below
// config.client.login_url  Client login page, for redirect in error cases
// config.client.app_url    Client success url, should handle the token
// config.api.token_url     LE API /auth/accessToken'
// config.api.authorize_url LE API /auth/acceptAuthorization

/*
  1. Client presents a “Login with Digital Living account” -button
  2. User clicks button and gets redirected to a backend server action, e.g. “/connect/life_engine”
  3. Backend server generates an unique “state” that can be checked securely, e.g. by:
  ```var now = Date.now().toString(16)
  var hash = hmac(secret, now)
  var state = JSON.stringify({t: now, h: hash})
  ```
  4. Backend server redirects user to authorize page with all the necessary arguments, i.e. client id, etc. as well as return URL and state
  5. Authorization page presents a login form, when submitting it the page takes care of validating login information with the Authorization backend (life engine)
  6. On successful login the authorization backend generates a single-use authorization code for the client ID, that is secured via the client secret, and returns it to the authorization page
  7. If the user has not yet accepted the LE terms, a dialog for accepting them is displayed.
  8. If the user accepts the terms, a LE API call is made. If not, the login is cancelled and the user is redirected to app login page.
  9. Authorization page redirects user back to callback URL with the state & authorization code
  10. Backend server validates state (e.g. regenerate hash with the given timestamp, check it matches and that it is recent enough)
  11. Backend server connects to the authorization backend to exchange the authorization code to an authorization token securely (uses client secret)
  12. Backend returns authorization token to client in a redirect url parameter
*/

import {config} from '../config'

log.info('Registering route GET /oauth')

const TIME_LIMIT = 10 * 60 * 1000 // NOTE: Arbitrary 10 minutes
const DEFAULT_LANGUAGE = 'EN'

/**
 * @api {get} /oauth
 */
app.get('/oauth', function (req, res) {

  const hmac = crypto.createHmac('sha256', config.secret.client_secret)

  log.info('received /oauth request')

  let now = Date.now().toString(16)
  hmac.update(now)
  let hash = hmac.digest('hex')
  //let state = JSON.stringify({t: now, h: hash})
  let state = {t: now, h: hash}

  let lang = req.query.lang ? req.query.lang : DEFAULT_LANGUAGE

  log.info('redirecting to /oauth url')
  res.redirect(config.OAuth_url + 'client_id=' + config.secret.client_id
    + '&redirect_uri=' + encodeURIComponent(config.callback_url)
    + '&state=' + encodeURIComponent(JSON.stringify(state))
    + '&lang=' + lang)

})

log.info('Registering route GET /oauth-callback')

app.get('/oauth-callback', function(req, res) {

  log.info('/oauth-callback')
  log.info(req.query)

  const state = JSON.parse(req.query.state)
  const shouldAuthorize = req.query.shouldAuthorize && req.query.shouldAuthorize === 'true'

  // Check timestamp from state
  const timestamp = +(new Number('0x' + state.t).toString(10))
  const now = new Date().getTime()

  const difference = now - timestamp

  const hmac = crypto.createHmac('sha256', config.secret.client_secret)
  hmac.update(state.t)
  let hash = hmac.digest('hex')

  // If time difference is not acceptable (eg. 5 minutes) or re-created hash doesn't match
  // redirect back to login page
  if (difference > TIME_LIMIT || hash !== state.h) {
    res.redirect(config.client.login_url)
  } else {
    const options = {
      method: 'POST',
      uri: config.api.token_url,
      resolveWithFullResponse: true,
      simple: false,
      json: true,
      form: {
        code: req.query.code,
        grant_type: 'authorization_code',
        client_id: config.secret.client_id,
        client_secret: config.secret.client_secret,
        redirect_uri: config.callback_url,
      },
    }

    request(options)
      .then(function (response) {

        if (response.statusCode === 200) {
          // User had not yet authorized the Application, so authorization endpoint must be called
          if (shouldAuthorize) {
            const authOptions = {
              method: 'POST',
              uri: config.api.authorize_url,
              headers: {
                Authorization: 'Bearer ' + response.body.access_token,
              },
            }
            return request.post(authOptions).then(function (authResponse) {
              // After authorization, return to app in logged in state
              return res.redirect(url.format({
                pathname: config.client.app_url,
                query: {
                  access_token: response.body.access_token,
                  refresh_token: response.body.refresh_token,
                },
              }))
            }).catch(function (err) {
              log.error(err)
              res.redirect(config.client.login_url)
            })
          } else {
            // Return to app in logged in state
            return res.redirect(url.format({
              pathname: config.client.app_url,
              query: {
                access_token: response.body.access_token,
                refresh_token: response.body.refresh_token,
              },
            }))
          }
        }
      }).catch(function (err) {
        res.redirect(config.client.login_url)
      }
    )
  }
})
