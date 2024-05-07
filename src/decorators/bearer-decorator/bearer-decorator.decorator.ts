'use strict';

import { ExecutionContext, createParamDecorator } from '@nestjs/common';

export const BearerDecorator = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    const headers: any = request.headers;
    let authorization: string = '1 2';
    for (const key in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, key)) {
        if (key === 'authorization' && typeof headers[key] === 'string') {
          authorization = headers[key];
        }
      }
    }
    let token: string = authorization.split(' ')[1];

    return token;
  },
);
