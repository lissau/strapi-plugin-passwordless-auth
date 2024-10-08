import { getTrad } from '../../../utils';

const layout = [
  {
    intlLabel: {
      id: getTrad('Settings.enabled.label'),
      defaultMessage: 'Settings.enabled.label',
    },
    description: {
      id: getTrad('Settings.enabled.description'),
      defaultMessage:
        'Settings.enabled.description',
    },
    name: 'enabled',
    type: 'bool',
    size: {
      col: 6,
      xs: 6,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.createUser.label'),
      defaultMessage: 'Settings.createUser.label',
    },
    description: {
      id: getTrad('Settings.createUser.description'),
      defaultMessage:
        'Settings.createUser.description',
    },
    name: 'createUserIfNotExists',
    type: 'bool',
    size: {
      col: 6,
      xs: 6,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.useSMS.label'),
      defaultMessage: 'Settings.useSMS.label',
    },
    description: {
      id: getTrad('Settings.useSMS.description'),
      defaultMessage:
        'Settings.useSMS.description',
    },
    name: 'useSMSVerification',
    type: 'bool',
    size: {
      col: 6,
      xs: 6,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.expire_period.label'),
      defaultMessage: 'Settings.expire_period.label',
    },
    description: {
      id: getTrad('Settings.expire_period.description'),
      defaultMessage: "Settings.expire_period.description",
    },
    name: 'expire_period',
    type: 'number',
    size: {
      col: 12,
      xs: 12,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.verificationUrl.label'),
      defaultMessage: 'Settings.verificationUrl.label',
    },
    description: {
      id: getTrad('Settings.verificationUrl.description'),
      defaultMessage: "Settings.verificationUrl.description",
    },
    name: 'verificationUrl',
    type: 'text',
    size: {
      col: 12,
      xs: 12,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.allowedCallbackDomains.label'),
      defaultMessage: 'Settings.allowedCallbackDomains.label',
    },
    description: {
      id: getTrad('Settings.allowedCallbackDomains.description'),
      defaultMessage: "Settings.allowedCallbackDomains.description",
    },
    name: 'allowedCallbackDomains',
    type: 'text',
    size: {
      col: 12,
      xs: 12,
    },
  },
  {
    intlLabel: {
      id: getTrad('Settings.jwt.issuer.label'),
      defaultMessage: 'Settings.jwt.issuer.label',
    },
    description: {
      id: getTrad('Settings.jwt.issuer.description'),
      defaultMessage: "Settings.jwt.issuer.description",
    },
    name: 'jwtIssuer',
    type: 'text',
    size: {
      col: 12,
      xs: 12,
    },
  },
  {
    intlLabel: {
      id: getTrad('Email.options.from.name.label'),
      defaultMessage: 'Email.options.from.name.label',
    },
    placeholder: {
      id: getTrad('Email.options.from.name.placeholder'),
      defaultMessage: 'Email.options.from.name.placeholder',
    },
    name: 'from_name',
    type: 'text',
    size: {
      col: 6,
      xs: 6,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('Email.options.from.email.label'),
      defaultMessage: 'Email.options.from.email.label',
    },
    placeholder: {
      id: getTrad('Email.options.from.email.placeholder'),
      defaultMessage: 'Email.options.from.email.placeholder',
    },
    name: 'from_email',
    type: 'email',
    size: {
      col: 6,
      xs: 6,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('SMS.options.from.label'),
      defaultMessage: 'SMS.options.from.label',
    },
    placeholder: {
      id: getTrad('SMS.options.from.placeholder'),
      defaultMessage: 'SMS.options.from.placeholder',
    },
    name: 'from_sms',
    type: 'text',
    size: {
      col: 6,
      xs: 6,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('Email.options.response_email.label'),
      defaultMessage: 'Email.options.response_email.label',
    },
    placeholder: {
      id: getTrad('Email.options.response_email.placeholder'),
      defaultMessage: 'Email.options.response_email.placeholder',
    },
    name: 'response_email',
    type: 'email',
    size: {
      col: 12,
      xs: 12,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('Email.options.object.label'),
      defaultMessage: 'Email.options.object.label',
    },
    placeholder: {
      id: getTrad('Email.options.object.placeholder'),
      defaultMessage: 'Email.options.object.placeholder',
    },
    name: 'object',
    type: 'text',
    size: {
      col: 12,
      xs: 12,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('Email.options.message_text.label'),
      defaultMessage: 'Email.options.object.label',
    },
    name: 'message_text',
    type: 'textarea',
    size: {
      col: 6,
      row: 7,
      xs: 6,
    },
    validations: {
      required: true
    }
  },
  {
    intlLabel: {
      id: getTrad('Email.options.message_html.label'),
      defaultMessage: 'Email.options.message_html.label',
    },
    name: 'message_html',
    type: 'textarea',
    size: {
      col: 6,
      row: 7,
      xs: 6,
    },
    validations: {
      required: true
    }
  },
];

export default layout;