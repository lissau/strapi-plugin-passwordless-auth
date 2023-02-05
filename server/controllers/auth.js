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
    const settings = await passwordless.settings();

    if (!settings.enabled) {
      return ctx.badRequest('Plugin disabled');
    }

    if(!settings.jwtIssuer) {
      return ctx.badRequest('JWT issuer is not configured')
    }

    if (_.isEmpty(receivedToken)) {
      return ctx.badRequest('Invalid token');
    }
    const token = await passwordless.fetchToken(receivedToken);

    if (!token || !token.is_active) {
      if(!token) {
        console.warn("User did not have a token when requesting login!")
      } else {
        console.info("User token was inactive")
      }
      return ctx.badRequest('Invalid token');
    }

    if(email !== token.email) {
      console.warn("User email did not match token email!")
      return ctx.badRequest('Invalid token');
    }

    if(nonce !== token.nonce) {
      console.warn("User nonce did not match token nonce!")
      return ctx.badRequest('Invalid token');
    }

    const isExpired = await passwordless.isTokenExpired(token);

    if (isExpired) {
      await passwordless.deactivateToken(token);
      console.info("User token is expired")
      return ctx.badRequest('Invalid token');
    }

    const config = strapi.config.get('plugin.passwordless')
    const populate = config.populate || []

    let user = await strapi.query('plugin::users-permissions.user').findOne({
      where: {email: token.email},
      populate: ['role', ...populate]
    });

    if (!user) {
      console.warn("Did not find a user matching token email")
      return ctx.badRequest('wrong.email');
    }

    if (user.blocked) {
      console.info("User was blocked")
      return ctx.badRequest('blocked.user');
    }

    if(config.beforeLogin) {
      const result = await config.beforeLogin(user, ctx)

      if(result) {
        return result()
      }
    }

    await passwordless.updateTokenOnLogin(token);

    const pluginStore = await strapi.store({
      environment: '',
      type: 'plugin',
      name: 'users-permissions',
    });
    const defaultRole = await pluginStore.get({key: 'advanced'});

    if(!user.role?.type || user.role?.type === "public") {
      const role = await strapi
      .query('plugin::users-permissions.role')
      .findOne({ where: { type: defaultRole.default_role } })

      user = await userService.edit(user.id, { 
        role: role.id,
        confirmed: true
      });
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

    let extraFields = {}
    try {
      extraFields = populate.reduce((prev, field) => ({...prev, [field]: user[field]}), {})
    } catch (e) {
      strapi.log.error("Unable to reduce populated fields to object", e)
    }

    ctx.send({
      jwt: jwtService.issue({
        id: user.id,
        role: user.role.type,
        ...extraFields,
        iss: settings.jwtIssuer,
        aud: "https://strapi-auth",
      }, {
        expiresIn: "180 days"
      }
      ),
      user: sanitizedUserInfo,
      context
    });
  },

  async sendLink(ctx) {
    const { passwordless } = strapi.plugins['passwordless'].services;

    const settings = await passwordless.settings();

    if (!settings.enabled) {
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
      return ctx.badRequest('wrong.user', e)
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