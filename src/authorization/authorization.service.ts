'use strict';

import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { SessionService } from 'src/common/session/session.service';
import { UserService } from 'src/common/user/user.service';
import { GeneratorService } from 'src/common/generator/generator.service';
import { access } from 'fs';
import { User } from 'src/common/user/user.entity';

@Injectable()
export class AuthorizationService {
  constructor(
    private users: UserService,
    private sessions: SessionService,
    private generator: GeneratorService,
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
    if (await this.chechEmail(email))
      throw new HttpException('Email is already taken', HttpStatus.BAD_REQUEST);
    if (await this.chechLogin(login))
      throw new HttpException('Login is already taken', HttpStatus.BAD_REQUEST);

    let user = new User();
    user.email = email;
    user.login = login;
    user.password = this.generator.hash([login, password]);
    user = await this.users.save(user);

    return JSON.stringify({
      id: user.id,
      accessToken: 'asd',
      accessTokenExpire: 1,
      refreshToken: 'zxc',
      refreshTokenExpire: 1,
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

  private async chechEmail(email: string): Promise<boolean> {
    return Boolean(await this.users.findByEmail(email));
  }

  private async chechLogin(login: string): Promise<boolean> {
    return Boolean(await this.users.findByLogin(login));
  }
}
