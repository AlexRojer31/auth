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
import { BaseStats } from './interfaces/base-stats/base-stats.interface';

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
      this.users.isUserService(user),
    );
    const refreshToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      this.users.isUserService(user),
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
      this.users.isUserService(user),
    );
    const refreshToken = await this.getToken(
      baseStats,
      user.id,
      session.id,
      this.users.isUserService(user),
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

    const payload = await this.getPayload(refreshToken);
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
        this.users.isUserService(user),
      );
      const newRefreshToken = await this.getToken(
        baseStats,
        user.id,
        updatedSession.id,
        this.users.isUserService(user),
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

  private async getPayload(token: string): Promise<JwtPayload | null> {
    try {
      return await this.jwt.verifyAsync<JwtPayload>(token, {
        secret: this.config.get<string>('SECRET_KEY') ?? 'local',
      });
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
    mixin: string,
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
        mixin: mixin,
      },
      exp: exp,
    };
  }

  private async getToken(
    baseStats: BaseStats,
    userId: string,
    sessionId: string,
    isService: boolean,
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
        isService,
        baseStats.mixin,
      ),
      {
        secret: this.config.get<string>('SECRET_KEY') ?? 'local',
      },
    );
  }

  private getBaseStats(ip: string, userAgent: string): BaseStats {
    const iat = this.getIat();
    return {
      iat: iat,
      exp: this.getExp(iat),
      expRefresh: this.getExp(iat, true),
      deviceHash: this.getDeviceHash(ip, userAgent),
      mixin:
        this.generator.getRandomNumbersString(32) +
        '-' +
        this.generator.generateUuid(),
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
