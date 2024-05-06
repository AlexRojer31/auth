'use strict';

import { IsIP, IsJWT, IsNotEmpty, IsString } from 'class-validator';

export class CheckTokenDto {
  @IsNotEmpty()
  @IsJWT()
  readonly accessToken: string;

  @IsNotEmpty()
  @IsString()
  readonly userAgent: string;

  @IsNotEmpty()
  @IsString()
  @IsIP()
  readonly userIp: string;
}
