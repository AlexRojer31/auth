'use strict';

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AbstractBaseBearerGuard } from '../abstract-base-bearer-guard/abstract-base-bearer-guard';
import { AuthService } from 'src/common/auth/auth.service';
import { Reflector } from '@nestjs/core';

@Injectable()
export class UserBearerGuard
  extends AbstractBaseBearerGuard
  implements CanActivate
{
  constructor(
    protected auth: AuthService,
    protected reflector: Reflector,
  ) {
    super(auth, reflector);
  }

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    return this.checkToken(context, AbstractBaseBearerGuard.USER_TYPE);
  }
}
