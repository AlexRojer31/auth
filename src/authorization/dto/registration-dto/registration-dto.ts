'use strict';

import { IsEmail, IsNotEmpty, IsStrongPassword } from 'class-validator';

export class RegistrationDto {
  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

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
