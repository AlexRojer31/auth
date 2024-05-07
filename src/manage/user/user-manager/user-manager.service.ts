'use strict';

import { Injectable } from '@nestjs/common';
import { AuthService } from 'src/common/auth/auth.service';
import { SessionService } from 'src/common/session/session.service';

@Injectable()
export class UserManagerService {
  constructor(
    private sessions: SessionService,
    private auth: AuthService,
  ) {}

  public async logout(token: string, all: boolean = false): Promise<boolean> {
    const payload = await this.auth.getPayload(token);
    if (payload) {
      if (all) {
        this.sessions.deleteByUuid(payload.aud.userId);
      } else {
        this.sessions.deleteById(payload.aud.sessionId);
      }

      return true;
    }

    return false;
  }
}
