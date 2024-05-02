'use strict';

import { Injectable } from '@nestjs/common';
import { SessionService } from 'src/common/session/session.service';
import { UserService } from 'src/common/user/user.service';
import { RefreshDto } from './dto/refresh-dto/refresh-dto';

@Injectable()
export class AuthorizationService {
  constructor(
    private users: UserService,
    private sessions: SessionService,
  ) {}

  public async registration(
    email: string,
    login: string,
    password: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<string> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      registrationDto: {
        email: email,
        login: login,
        password: password,
      },
      ip: ip,
      userAgent: userAgent,
    });
  }

  public async login(
    login: string,
    password: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<string> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      loginDto: {
        login: login,
        password: password,
      },
      ip: ip,
      userAgent: userAgent,
    });
  }

  public async refresh(
    refreshToken: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<string> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      refreshToken: refreshToken,
      ip: ip,
      userAgent: userAgent,
    });
  }
}
