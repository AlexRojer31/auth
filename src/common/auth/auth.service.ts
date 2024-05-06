'use strict';

import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { GeneratorService } from '../generator/generator.service';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './interfaces/jwt-payload/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private jwt: JwtService,
    private generator: GeneratorService,
    private config: ConfigService,
  ) {}

  public getDeviceHash(ip: string, userAgent: string): string {
    return this.generator.hash([ip, userAgent]);
  }

  public async getPayload(token: string): Promise<JwtPayload | null> {
    try {
      return await this.jwt.verifyAsync<JwtPayload>(token, {
        secret: this.config.get<string>('SECRET_KEY') ?? 'local',
      });
    } catch (e) {
      return null;
    }
  }

  public getIat(): number {
    return +this.generator.getUnixTimestamp();
  }

  public getExp(iat: number, isRefresh: boolean = false): number {
    let exp = 0;
    if (isRefresh) {
      exp = +(this.config.get<number>('REFRESH_TOKEN_EXPIRE_SECONDS') ?? 0);
    } else {
      exp = +(this.config.get<number>('ACCESS_TOKEN_EXPIRE_SECONDS') ?? 0);
    }

    return iat + exp;
  }
}
