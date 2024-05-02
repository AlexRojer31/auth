'use strict';

import { Injectable } from '@nestjs/common';
import { SessionService } from 'src/common/session/session.service';
import { UserService } from 'src/common/user/user.service';
import { RegistrationDto } from './dto/registration-dto/registration-dto';
import { LoginDto } from './dto/login-dto/login-dto';
import { RefreshDto } from './dto/refresh-dto/refresh-dto';

@Injectable()
export class AuthorizationService {
  constructor(
    private users: UserService,
    private sessions: SessionService,
  ) {}

  public async registration(
    registrationDto: RegistrationDto,
    ip: string,
    userAgent: string | undefined,
  ): Promise<string> {
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      registrationDto: registrationDto,
      ip: ip,
      userAgent: userAgent,
    });
  }

  public async login(
    loginDto: LoginDto,
    ip: string,
    userAgent: string | undefined,
  ): Promise<string> {
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      loginDto: loginDto,
      ip: ip,
      userAgent: userAgent,
    });
  }

  public async refresh(
    refreshDto: RefreshDto,
    ip: string,
    userAgent: string | undefined,
  ): Promise<string> {
    if (userAgent === undefined) userAgent = 'unknown';

    return JSON.stringify({
      refreshDto: refreshDto,
      ip: ip,
      userAgent: userAgent,
    });
  }
}
