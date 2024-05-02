'use strict';

import { v4 as uuidv4 } from 'uuid';
import { Injectable } from '@nestjs/common';
import { createHmac } from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GeneratorService {
  constructor(private configService: ConfigService) {}

  public getRandomNumber(): number {
    return Math.floor(Math.random() * 9);
  }

  public generateUuid(): string {
    return uuidv4();
  }

  public getRandomNumbersString(length: number): string {
    let key = '';
    for (let i = 0; i < length; i++) {
      key += this.getRandomNumber().toString();
    }

    return key;
  }

  public hash(strings: string[]): string {
    let hash = createHmac(
      'sha256',
      this.configService.get<string>('SALT') ?? 'local',
    )
      .update(this.joinStringsBeforeHashing(strings))
      .digest('hex');
    return hash;
  }

  public compare(strings: string[], hash: string): boolean {
    return this.hash(strings) === hash;
  }

  private joinStringsBeforeHashing(strings: string[]): string {
    return strings.join('.');
  }
}
