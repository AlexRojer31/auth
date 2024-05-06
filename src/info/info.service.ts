'use strict';

import { Injectable } from '@nestjs/common';
import { AuthService } from 'src/common/auth/auth.service';
import { GeneratorService } from 'src/common/generator/generator.service';

@Injectable()
export class InfoService {
  constructor(
    private generator: GeneratorService,
    private auth: AuthService,
  ) {}

  public async checkToken(
    token: string,
    userAgent: string,
    userIp: string,
  ): Promise<boolean> {
    const payload = await this.auth.getPayload(token);
    const hash = this.auth.getDeviceHash(userIp, userAgent);
    if (payload)
      return (
        payload.aud.deviceHash === hash &&
        payload.exp > this.generator.getUnixTimestamp()
      );

    return false;
  }
}
