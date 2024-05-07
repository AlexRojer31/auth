'use strict';

import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { SessionService } from 'src/common/session/session.service';
import { UserService } from 'src/common/user/user.service';
import { GeneratorService } from 'src/common/generator/generator.service';
import { User } from 'src/common/user/user.entity';
import { Session } from 'src/common/session/session.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SuccessAuth } from './interfaces/success-auth/success-auth.interface';
import { BaseStats } from './interfaces/base-stats/base-stats.interface';
import { JwtPayload } from 'src/common/auth/interfaces/jwt-payload/jwt-payload.interface';
import { AuthService } from 'src/common/auth/auth.service';

@Injectable()
export class AuthorizationService {
  constructor(
    private users: UserService,
    private sessions: SessionService,
    private generator: GeneratorService,
    private config: ConfigService,
    private jwt: JwtService,
    private auth: AuthService,
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

    const baseStats = this.getBaseStats(ip, userAgent);
    const session = await this.createSession(
      user.id,
      baseStats.deviceHash,
      baseStats.mixin,
    );
    if (!session)
      throw new HttpException(
        'Something went wrong, please try again',
        HttpStatus.BAD_REQUEST,
      );

    const accessToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      user.rights,
    );
    const refreshToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      user.rights,
      true,
    );

    return this.getSuccessAuth(
      user.id,
      accessToken,
      baseStats.exp,
      refreshToken,
      baseStats.expRefresh,
    );
  }

  public async login(
    login: string,
    password: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<SuccessAuth> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';

    const user = await this.users.findByLogin(login);
    if (!user) throw new HttpException('Invalid login', HttpStatus.BAD_REQUEST);
    if (!this.validatePasswordHash(login, password, user.password))
      throw new HttpException('Invalid granted', HttpStatus.BAD_REQUEST);

    const baseStats = this.getBaseStats(ip, userAgent);
    const session = await this.createSession(
      user.id,
      baseStats.deviceHash,
      baseStats.mixin,
    );
    if (!session)
      throw new HttpException(
        'Something went wrong, please try again',
        HttpStatus.BAD_REQUEST,
      );

    const accessToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      user.rights,
    );
    const refreshToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      user.rights,
      true,
    );

    return this.getSuccessAuth(
      user.id,
      accessToken,
      baseStats.exp,
      refreshToken,
      baseStats.expRefresh,
    );
  }

  public async refresh(
    refreshToken: string,
    ip: string | undefined,
    userAgent: string | undefined,
  ): Promise<SuccessAuth> {
    if (ip === undefined) ip = '0.0.0.0';
    if (userAgent === undefined) userAgent = 'unknown';

    const payload = await this.auth.getPayload(refreshToken);
    if (!payload)
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);

    const session = await this.sessions.find(payload.aud.sessionId);
    if (!session || session.mixin !== payload.aud.mixin)
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);

    const user = await this.users.find(payload.aud.userId);
    if (!user) throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);

    const baseStats = this.getBaseStats(ip, userAgent);
    session.mixin = baseStats.mixin;
    try {
      const updatedSession = await this.sessions.save(session);

      const accessToken = await this.getToken(
        baseStats,
        user.id,
        updatedSession.id,
        user.rights,
      );
      const newRefreshToken = await this.getToken(
        baseStats,
        user.id,
        updatedSession.id,
        user.rights,
        true,
      );

      return this.getSuccessAuth(
        user.id,
        accessToken,
        baseStats.exp,
        newRefreshToken,
        baseStats.expRefresh,
      );
    } catch (e) {
      throw new HttpException(
        'Something went wrong, please try again',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  private async createUser(
    email: string,
    login: string,
    password: string,
  ): Promise<User | null> {
    let user = new User();
    user.email = email;
    user.login = login;
    user.password = this.generatePasswordHash(login, password);
    try {
      return await this.users.save(user);
    } catch (e) {
      return null;
    }
  }

  private generatePasswordHash(login: string, password: string): string {
    return this.generator.hash([login, password]);
  }

  private validatePasswordHash(
    login: string,
    password: string,
    hash: string,
  ): boolean {
    return this.generator.compare([login, password], hash);
  }

  private async createSession(
    userId: string,
    deviceHash: string,
    mixin: string,
  ): Promise<Session | null> {
    let session = new Session();
    session.uuid = userId;
    session.deviceHash = deviceHash;
    session.mixin = mixin;
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
    rights: number = 0,
    mixin: string,
  ): JwtPayload {
    return {
      iss: 'auth',
      iat: iat,
      sub: isRefresh ? 'refreshToken' : 'accessToken',
      aud: {
        userId: userId,
        rights: rights,
        sessionId: sessionId,
        deviceHash: deviceHash,
        mixin: mixin,
      },
      exp: exp,
    };
  }

  private async getToken(
    baseStats: BaseStats,
    userId: string,
    sessionId: string,
    rights: number,
    isRefresh: boolean = false,
  ): Promise<string> {
    return this.jwt.signAsync(
      this.generatePayload(
        baseStats.iat,
        userId,
        sessionId,
        baseStats.deviceHash,
        !isRefresh ? baseStats.exp : baseStats.expRefresh,
        isRefresh,
        rights,
        baseStats.mixin,
      ),
      {
        secret: this.config.get<string>('SECRET_KEY') ?? 'local',
      },
    );
  }

  private getBaseStats(ip: string, userAgent: string): BaseStats {
    const iat = this.auth.getIat();
    return {
      iat: iat,
      exp: this.auth.getExp(iat),
      expRefresh: this.auth.getExp(iat, true),
      deviceHash: this.auth.getDeviceHash(ip, userAgent),
      mixin:
        this.generator.getRandomNumbersString(32) +
        '-' +
        this.generator.generateUuid(),
    };
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
