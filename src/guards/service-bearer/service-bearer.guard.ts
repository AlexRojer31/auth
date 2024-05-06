'use strict';

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { AbstractBaseBearerGuard } from '../abstract-base-bearer/abstract-base-bearer.guard';
import { AuthService } from 'src/common/auth/auth.service';

@Injectable()
export class ServiceBearerGuard
  extends AbstractBaseBearerGuard
  implements CanActivate
{
  constructor(protected auth: AuthService) {
    super(auth);
  }

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    return this.checkToken(context, AbstractBaseBearerGuard.SERVICE_TYPE);
  }
}
