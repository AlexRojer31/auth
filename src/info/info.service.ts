'use strict';

import { Injectable } from '@nestjs/common';
import { AuthService } from 'src/common/auth/auth.service';

@Injectable()
export class InfoService {
  constructor(private auth: AuthService) {}

  public async checkToken(
    token: string,
    userAgent: string,
    userIp: string,
  ): Promise<boolean> {
    return this.auth.checkToken(token, userAgent, userIp);
  }
}
