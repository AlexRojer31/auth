'use strict';

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from 'src/authorization/interfaces/jwt-payload/jwt-payload.interface';
import { GeneratorService } from 'src/common/generator/generator.service';

@Injectable()
export class InfoService {
  constructor(
    private jwt: JwtService,
    private generator: GeneratorService,
    private config: ConfigService,
  ) {}

  public async checkToken(
    token: string,
    userAgent: string,
    userIp: string,
  ): Promise<boolean> {
    const payload = await this.getPayload(token);
    const hash = this.getDeviceHash(userIp, userAgent);
    if (payload)
      return (
        payload.aud.deviceHash === hash &&
        payload.exp > this.generator.getUnixTimestamp()
      );

    return false;
  }

  private getDeviceHash(ip: string, userAgent: string): string {
    return this.generator.hash([ip, userAgent]);
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
}
