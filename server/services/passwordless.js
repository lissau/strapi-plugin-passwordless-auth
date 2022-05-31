'use strict';

/**
 * passwordless.js service
 *
 * @description: A set of functions similar to controller's actions to avoid code duplication.
 */

const _ = require("lodash");
const crypto = require("crypto");
const {sanitize} = require('@strapi/utils');

module.exports = (
  {
    strapi
  }
) => {
  return {

    async initialize() {
    },

    settings() {
      const pluginStore = strapi.store({
        environment: '',
        type: 'plugin',
        name: 'passwordless',
      });
      return pluginStore.get({key: 'settings'});
    },

    userSettings() {
      const pluginStore = strapi.store({
        environment: '',
        type: 'plugin',
        name: 'users-permissions',
      });
      return pluginStore.get({key: 'advanced'});
    },

    async isEnabled() {
      const settings = await this.settings();
      return !!settings.enabled;
    },

    async createUser(user) {
      const userSettings = await this.userSettings();
      const role = await strapi
        .query('plugin::users-permissions.role')
        .findOne({type: userSettings.default_role}, []);

      const newUser = {
        email: user.email,
        username: user.username || user.email,
        role: {id: role.id}
      };
      return strapi
        .query('plugin::users-permissions.user')
        .create({data: newUser, populate: ['role']});
    },

    async user(email, username) {

      const service = strapi.query('plugin::users-permissions.user')
      
      if(email || username) {
        
        const user = await service.findOne({
          where: email ? { email } : { username }
        });

        if (user) {
          return user;
        }

        // CHECK THAT THE CALL TO userService did succeed, and did not find a user BEFORE
        // creating a new user
      }

      const settings = await this.settings();

      console.log({email, username, settings})

      if (email && settings.createUserIfNotExists) {
        return this.createUser({email, username})
      }

      return false;
      
    },

    async sendLoginLink(token, callbackUrl) {
      const settings = await this.settings();
      const user = await strapi.query('plugin::users-permissions.user').findOne({
        where: {email: token.email}
      });
      const userSchema = strapi.getModel('plugin::users-permissions.user');
      // Sanitize the template's user information
      const sanitizedUserInfo = await sanitize.sanitizers.defaultSanitizeOutput(userSchema, user);

      const text = this.template(settings.message_text, {
        URL: settings.verificationUrl + "?token=" + token.body + "&callbackUrl=" + callbackUrl,
        CODE: token.body,
        USER: sanitizedUserInfo
      });

      const html = this.template(settings.message_html, {
        URL: settings.verificationUrl + "?token=" + token.body + "&callbackUrl=" + callbackUrl,
        CODE: token.body,
        USER: sanitizedUserInfo
      });

      const subject = this.template(settings.object, {
        URL: settings.verificationUrl + "?token=" + token.body + "&callbackUrl=" + callbackUrl,
        CODE: token.body,
        USER: sanitizedUserInfo
      });

      const sendData = {
        to: token.email,
        from:
          settings.from_email && settings.from_name
            ? `${settings.from_name} <${settings.from_email}>`
            : undefined,
        replyTo: settings.response_email,
        subject,
        text,
        html,
      }
      // Send an email to the user.
      return await strapi
        .plugin('email')
        .service('email')
        .send(sendData);
    },

    async createToken(email, context) {
      const tokensService = strapi.query('plugin::passwordless.token');
      const body = crypto.randomBytes(20).toString('hex');
      const tokenInfo = {
        email,
        body,
        context: JSON.stringify(context),
        is_active: true
      };
      
      // Ensure only 1 active signin request
      const updatedToken = await tokensService.update({where: { email }, data: tokenInfo});
      if(updatedToken) {
        return updatedToken
      }

      const newToken = await tokensService.create({ data: tokenInfo });

      return newToken
    },

    updateTokenOnLogin(token) {
      const tokensService = strapi.query('plugin::passwordless.token');
      return tokensService.update({where: {id: token.id}, data: {is_active: false, login_date: new Date()}});
    },

    async isTokenExpired(token) {
      const settings = await this.settings();
      const tokenDate = new Date(token.login_date || token.createdAt).getTime() / 1000;
      const nowDate = new Date().getTime() / 1000;
      return nowDate - tokenDate <= settings.expire_period;
    },

    async deactivateToken(token) {
      const tokensService = strapi.query('plugin::passwordless.token');
      await tokensService.update(
        {where: {id: token.id}, data: {is_active: false}}
      );
    },

    fetchToken(body) {
      const tokensService = strapi.query('plugin::passwordless.token');
      return tokensService.findOne({where: {body}});
    },

    async hasRecentToken(email) {
      const tokensService = strapi.query('plugin::passwordless.token');

      const token = await tokensService.findOne({where: { email }});

      if(token && token.is_active !== false) {
        return this.isTokenExpired(token)
      } else {
        return false
      }
      
    },

    template(layout, data) {
      const compiledObject = _.template(layout);
      return compiledObject(data);
    }
  };
};
