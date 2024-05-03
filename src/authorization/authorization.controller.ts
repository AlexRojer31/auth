'use strict';

import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Param,
  Post,
} from '@nestjs/common';
import { AuthorizationService } from './authorization.service';
import { RegistrationDto } from './dto/registration-dto/registration-dto';
import { LoginDto } from './dto/login-dto/login-dto';
import { RefreshDto } from './dto/refresh-dto/refresh-dto';
import { SuccessAuth } from './interfaces/success-auth/success-auth.interface';

@Controller('auth')
export class AuthorizationController {
  constructor(private service: AuthorizationService) {}

  @Post('registration')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async registration(
    @Body() dto: RegistrationDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<SuccessAuth> {
    return this.service.registration(
      dto.email,
      dto.login,
      dto.password,
      ip,
      userAgent,
    );
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async login(
    @Body() dto: LoginDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<SuccessAuth> {
    return this.service.login(dto.login, dto.password, ip, userAgent);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async refresh(
    @Body() dto: RefreshDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<string> {
    return this.service.refresh(dto.refreshToken, ip, userAgent);
  }
}
