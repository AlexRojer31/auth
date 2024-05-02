'use strict';

import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { SessionService } from 'src/common/session/session.service';
import { UserService } from 'src/common/user/user.service';
import { GeneratorService } from 'src/common/generator/generator.service';
import { User } from 'src/common/user/user.entity';
import { Session } from 'src/common/session/session.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './interfaces/jwt-payload/jwt-payload.interface';
import { SuccessAuth } from './interfaces/success-auth/success-auth.interface';

@Injectable()
export class AuthorizationService {
  constructor(
    private users: UserService,
    private sessions: SessionService,
    private generator: GeneratorService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  public async registration(
    email: string,
    login: string,
    password: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<SuccessAuth> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';
    if (await this.users.checkEmail(email))
      throw new HttpException('Email is already taken', HttpStatus.BAD_REQUEST);
    if (await this.users.checkLogin(login))
      throw new HttpException('Login is already taken', HttpStatus.BAD_REQUEST);

    const user = await this.createUser(email, login, password);
    if (!user)
      throw new HttpException(
        'Something went wrong, please try again',
        HttpStatus.BAD_REQUEST,
      );

    const iat = this.getIat();
    const exp = this.getExp(iat);
    const expRefresh = this.getExp(iat, true);
    const deviceHash = this.getDeviceHash(ip, userAgent);

    const session = await this.createSession(user.id, deviceHash);
    if (!session)
      throw new HttpException(
        'Something went wrong, please try again',
        HttpStatus.BAD_REQUEST,
      );

    const payloadAccess = this.generatePayload(
      iat,
      user.id,
      session.id,
      deviceHash,
      exp,
      false,
      user.isService,
    );
    const accessToken = await this.jwt.signAsync(payloadAccess, {
      secret: this.config.get<string>('SECRET_KEY') ?? 'local',
    });
    const payloadRefresh = this.generatePayload(
      iat,
      user.id,
      session.id,
      deviceHash,
      expRefresh,
      true,
      user.isService,
    );
    const refreshToken = await this.jwt.signAsync(payloadRefresh, {
      secret: this.config.get<string>('SECRET_KEY') ?? 'local',
    });

    return this.getSuccessAuth(
      user.id,
      accessToken,
      exp,
      refreshToken,
      expRefresh,
    );
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

  private async createUser(
    email: string,
    login: string,
    password: string,
  ): Promise<User | null> {
    let user = new User();
    user.email = email;
    user.login = login;
    user.password = this.generator.hash([login, password]);
    try {
      return await this.users.save(user);
    } catch (e) {
      return null;
    }
  }

  private async createSession(
    userId: string,
    deviceHash: string,
  ): Promise<Session | null> {
    let session = new Session();
    session.uuid = userId;
    session.deviceHash = deviceHash;
    try {
      return await this.sessions.save(session);
    } catch (e) {
      return null;
    }
  }

  private generatePayload(
    iat: number,
    userId: string,
    sessionId: string,
    deviceHash: string,
    exp: number,
    isRefresh: boolean = false,
    isService: boolean = false,
  ): JwtPayload {
    return {
      iss: 'auth',
      iat: iat,
      sub: isRefresh ? 'refreshToken' : 'accessToken',
      aud: {
        client: isService ? 'service' : 'user',
        userId: userId,
        sessionId: sessionId,
        deviceHash: deviceHash,
        mixin: this.generator.getRandomNumbersString(32),
      },
      exp: exp,
    };
  }

  private getDeviceHash(ip: string, userAgent: string): string {
    return this.generator.hash([ip, userAgent]);
  }

  private getIat(): number {
    return +this.generator.getUnixTimestamp();
  }

  private getExp(iat: number, isRefresh: boolean = false): number {
    let exp = 0;
    if (isRefresh) {
      exp = +(this.config.get<number>('REFRESH_TOKEN_EXPIRE_SECONDS') ?? 0);
    } else {
      exp = +(this.config.get<number>('ACCESS_TOKEN_EXPIRE_SECONDS') ?? 0);
    }

    return iat + exp;
  }

  private getSuccessAuth(
    userId: string,
    accessToken: string,
    accessTokenExpire: number,
    refreshToken: string,
    refreshTokenExpire: number,
  ): SuccessAuth {
    return {
      id: userId,
      accessToken: accessToken,
      accessTokenExpire: accessTokenExpire,
      refreshToken: refreshToken,
      refreshTokenExpire: refreshTokenExpire,
    };
  }
}
