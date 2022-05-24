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
    const {token: receivedToken, callbackUrl} = ctx.query;
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

    const settings = await passwordless.settings()

    const allowedCallbackUrls = settings.allowedCallbackUrls ? settings.allowedCallbackUrls.split(",") : []

    if(allowedCallbackUrls.length < 0) {
      return ctx.badRequest("No allowed callback urls specified in settings")
    }
    
    if(!allowedCallbackUrls.includes(callbackUrl)) {
      return ctx.badRequest("Invalid callback url")
    }

    const isValid = await passwordless.isTokenValid(token);

    if (!isValid) {
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

    ctx.redirect(callbackUrl)
    const jwt = jwtService.issue({id: user.id})
    ctx.cookies.set("token", jwt, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      maxAge: 1000 * 60 * 60 * 24 * 30, // 30 Day Age
      domain: process.env.NODE_ENV === "development" ? "localhost" : process.env.PRODUCTION_URL,
    });
    
    ctx.send({
      status: "Authenticated",
      user: sanitizedUserInfo,
      context
    });
  },
  async logout(ctx) {

    ctx.cookies.set("token", null);
    ctx.send({
      authorized: true,
      message: "Successfully destroyed session",
    });

  },
  async sendLink(ctx) {
    const { passwordless } = strapi.plugins['passwordless'].services;

    const isEnabled = await passwordless.isEnabled();

    if (!isEnabled) {
      return ctx.badRequest('plugin.disabled');
    }

    const params = _.assign(ctx.request.body);
    if(!params.callbackUrl) {
      return ctx.badRequest("Missing callbackUrl parameter")
    }

    const username = params.username || null;

    const email = params.email ? params.email.trim().toLowerCase() : null;
    const isEmail = emailRegExp.test(email);
    if (email && !isEmail) {
      return ctx.badRequest('wrong.email');
    }

    // Test if an email was already sent with a valid token
    const hasRecentToken = await passwordless.hasRecentToken(email)
    if(hasRecentToken) {
      return ctx.tooManyRequests("Token already sent")
    }

    const settings = await passwordless.settings()

    const allowedCallbackUrls = settings.allowedCallbackUrls ? settings.allowedCallbackUrls.split(",") : []

    if(allowedCallbackUrls.length < 0) {
      return ctx.badRequest("No allowed callback urls specified in settings")
    }
    
    if(!allowedCallbackUrls.includes(params.callbackUrl)) {
      return ctx.badRequest("Invalid callback url")
    }

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
      await passwordless.sendLoginLink(token, params.callbackUrl);
      ctx.send({
        email,
        username,
        sent: true,
      });
    } catch (err) {
      return ctx.badRequest(err);
    }
  },
};