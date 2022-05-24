'use strict';

module.exports = async (ctx, next) => {
  
  if (ctx.request && ctx.request.header && !ctx.request.header.authorization) {
    const token = ctx.cookies.get("token");
    if (token) {
      ctx.request.header.authorization = "Bearer " + token;
    }
  }

  if (!ctx.state.user) {
    return ctx.unauthorized();
  }

  await next();
};
