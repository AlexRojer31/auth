'use strict';

import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from 'src/common/auth/auth.service';
import { Right } from 'src/common/rights/right.enum';
import { USER_RIGHTS_KEY } from 'src/decorators/rights/rights.decorator';

export abstract class AbstractBaseBearerGuard {
  static SERVICE_TYPE = 'service';
  static USER_TYPE = 'user';

  constructor(
    protected auth: AuthService,
    protected reflector: Reflector,
  ) {}

  protected async checkToken(
    context: ExecutionContext,
    bearerType: string,
  ): Promise<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      const headers: any = request.headers;
      let userAgent: string = '';
      let authorization: string = '';
      const ip: string = request.ip;
      for (const key in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, key)) {
          if (key === 'user-agent' && typeof headers[key] === 'string') {
            userAgent = headers[key];
          }
          if (key === 'authorization' && typeof headers[key] === 'string') {
            authorization = headers[key];
          }
        }
      }
      let token: string = authorization.split(' ')[1];
      const rights = this.reflector.getAllAndOverride<Right[]>(
        USER_RIGHTS_KEY,
        [context.getHandler(), context.getClass()],
      );
      if (ip && userAgent && token) {
        return this.auth.checkToken(token, userAgent, ip, rights);
        // switch (bearerType) {
        //   case AbstractBaseBearerGuard.USER_TYPE:
        //     return this.auth.checkToken(token, userAgent, ip);
        //   case AbstractBaseBearerGuard.SERVICE_TYPE:
        //     return this.auth.checkServiceToken(token, userAgent, ip);
        //   default:
        //     return false;
        // }
      }

      return false;
    } catch (e) {
      return false;
    }
  }
}
