'use strict';
/**
 * Auth.js controller
 *
 * @description: A set of functions called "actions" for managing `Auth`.
 */

const {sanitize} = require('@strapi/utils');

/* eslint-disable no-useless-escape */
const _ = require('lodash');
const emailRegExp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

module.exports = {
  async login(ctx) {
    const {token: receivedToken, email, nonce} = ctx.query;
    const {passwordless} = strapi.plugins['passwordless'].services;
    const {user: userService, jwt: jwtService} = strapi.plugins['users-permissions'].services;
    const isEnabled = await passwordless.isEnabled();

    if (!isEnabled) {
      return ctx.badRequest('Plugin disabled');
    }

    if (_.isEmpty(receivedToken)) {
      return ctx.badRequest('Invalid token');
    }
    const token = await passwordless.fetchToken(receivedToken);

    if (!token || !token.is_active) {
      return ctx.badRequest('Invalid token');
    }

    if(email !== token.email) {
      return ctx.badRequest('Invalid token');
    }

    if(nonce !== token.nonce) {
      return ctx.badRequest('Invalid token');
    }

    const isExpired = await passwordless.isTokenExpired(token);

    if (!isExpired) {
      await passwordless.deactivateToken(token);
      return ctx.badRequest('token.invalid');
    }

    await passwordless.updateTokenOnLogin(token);

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: {email: token.email}
    });

    if (!user) {
      return ctx.badRequest('wrong.email');
    }

    if (user.blocked) {
      return ctx.badRequest('blocked.user');
    }

    if (!user.confirmed) {
      await userService.edit(user.id, { confirmed: true });
    }
    const userSchema = strapi.getModel('plugin::users-permissions.user');
    // Sanitize the template's user information
    const sanitizedUserInfo = await sanitize.sanitizers.defaultSanitizeOutput(userSchema, user);

    let context;
    try {
      context = JSON.parse(token.context);
    } catch (e) {
      context = {}
    }

    ctx.send({
      jwt: jwtService.issue({
        id: user.id,
        iss: "https://cykelejer.dk/",
        aud: "https://strapi-auth",
      }, {
        expiresIn: "14 days"
      }
      ),
      user: sanitizedUserInfo,
      context
    });
  },

  async sendLink(ctx) {
    const { passwordless } = strapi.plugins['passwordless'].services;

    const isEnabled = await passwordless.isEnabled();

    if (!isEnabled) {
      return ctx.badRequest('plugin.disabled');
    }

    const params = _.assign(ctx.request.body);

    const username = params.username || null;

    const email = params.email ? params.email.trim().toLowerCase() : null;
    const isEmail = emailRegExp.test(email);
    if (email && !isEmail) {
      return ctx.badRequest('wrong.email');
    }

    // Test if an email was already sent with a valid token
    // const hasRecentToken = await passwordless.hasRecentToken(email)
    // if(hasRecentToken) {
    //   return ctx.tooManyRequests("Token already sent")
    // }

    let user;
    try {
      user = await passwordless.user(email, username);
    } catch (e) {
      return ctx.badRequest('wrong.user')
    }

    if (!user) {
      return ctx.badRequest('wrong.email');
    }

    if (email && user.email !== email) {
      return ctx.badRequest('wrong.user')
    }

    if (user.blocked) {
      return ctx.badRequest('blocked.user');
    }

    try {
      const context = params.context || {};
      const token = await passwordless.createToken(user.email, context);

      await passwordless.sendLoginLink(token);

      ctx.send({
        email,
        username,
        nonce: token.nonce,
        sent: true,
      });
    } catch (err) {
      return ctx.badRequest(err);
    }
  },
};