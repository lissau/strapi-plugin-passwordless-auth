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

  const sendEmail = async (
    {
      template,
      userInfo,
      token,
      settings
    }
    ) => {

    const text = template(settings.message_text, {
      URL: settings.verificationUrl + "?token=" + token.body,
      CODE: token.body,
      USER: userInfo
    });
  
    const html = template(settings.message_html, {
      URL: settings.verificationUrl + "?token=" + token.body,
      CODE: token.body,
      USER: userInfo
    });
  
    const subject = template(settings.object, {
      URL: settings.verificationUrl + "?token=" + token.body,
      CODE: token.body,
      USER: userInfo
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
  
  }
  
  const sendSMS = async ({
    template,
    to,
    token,
    settings
  }) => {
  
    const { twilio } = strapi.config.get('plugin.passwordless')

    if(!twilio) {
      return ctx.internalError("Invalid configuration")
    }

    const client = require('twilio')(twilio.accountSID, twilio.authToken);

    const text = template(settings.message_text, {
      CODE: token.body
    });

    const response = await client.messages
    .create({
      body: text,
      from: settings.from_sms,
      to
    })

    return response
  
  }

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

    async createUser(user) {
      const role = await strapi
        .query('plugin::users-permissions.role')
        .findOne({ where: {type: 'public'}});

      if(!role) {
        throw new Error("No public role found")
      }

      const newUser = {
        username: user.username || user.email || user.phonenumber,
        role: {id: role.id}
      };
      
      if(user.email) {
        newUser.email = user.email
      }

      if(user.phonenumber) {
        newUser.phonenumber = user.phonenumber
      }

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

      if (email && settings.createUserIfNotExists) {
        return this.createUser({email, username})
      }

      return false;
      
    },

    async sendLoginLink(token) {
      const settings = await this.settings();
      const user = await strapi.query('plugin::users-permissions.user').findOne({
        where: {email: token.email}
      });
      const userSchema = strapi.getModel('plugin::users-permissions.user');
      // Sanitize the template's user information
      const sanitizedUserInfo = await sanitize.sanitizers.defaultSanitizeOutput(userSchema, user);

      const channel = settings.useSMSVerification ? "sms" : "email"

      if(channel === "sms") {
        return await sendSMS({
          template: this.template,
          to: user.phonenumber,
          token, 
          settings
        })
      } else {
        return await sendEmail({
          template: this.template,
          userInfo: sanitizedUserInfo,
          token,
          settings
        })
      }
    },

    async createToken(email, context) {
      const tokensService = strapi.query('plugin::passwordless.token');

      // No 0 and O
      const combinations = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

      const codeLength = 4
      // 34^4 = 1336336 combinations
      // KuCoin uses letters only 10^4=1 million. 

      let body = ""
      for (var i = 0; i < codeLength; i++) {
        body += combinations.charAt(crypto.randomInt(0, combinations.length - 1));
      }

      const nonce = crypto.randomBytes(20).toString('hex');

      const tokenInfo = {
        email,
        body,
        context: JSON.stringify(context),
        is_active: true,
        nonce
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
      const tokenDate = new Date(token.updatedAt).getTime() / 1000;
      const nowDate = new Date().getTime() / 1000;

      return nowDate - tokenDate > settings.expire_period;
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
        return !this.isTokenExpired(token)
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
