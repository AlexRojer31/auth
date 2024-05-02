'use strict';

import { IsJWT, IsNotEmpty } from 'class-validator';

export class RefreshDto {
  @IsNotEmpty()
  @IsJWT()
  readonly refreshToken: string;
}
