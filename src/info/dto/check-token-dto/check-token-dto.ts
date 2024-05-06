'use strict';

import { IsJWT, IsNotEmpty, IsString } from 'class-validator';

export class CheckTokenDto {
  @IsNotEmpty()
  @IsJWT()
  readonly accessToken: string;

  @IsNotEmpty()
  @IsString()
  readonly userAgent: string;

  @IsNotEmpty()
  @IsString()
  readonly userIp: string;
}
