'use strict';

import { IsNotEmpty, IsStrongPassword } from 'class-validator';

export class LoginDto {
  @IsStrongPassword({
    minLength: 4,
    minNumbers: 0,
    minSymbols: 0,
    minUppercase: 0,
  })
  @IsNotEmpty()
  readonly login: string;

  @IsStrongPassword({
    minLength: 4,
    minNumbers: 0,
    minSymbols: 0,
    minUppercase: 0,
  })
  @IsNotEmpty()
  readonly password: string;
}
