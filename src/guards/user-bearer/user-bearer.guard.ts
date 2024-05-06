'use strict';

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AuthService } from 'src/common/auth/auth.service';

@Injectable()
export class UserBearerGuard implements CanActivate {
  constructor(private auth: AuthService) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
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
      if (ip && userAgent && token) {
        return this.auth.checkToken(token, userAgent, ip);
      }

      return false;
    } catch (e) {
      return false;
    }
  }
}
