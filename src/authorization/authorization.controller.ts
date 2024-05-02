'use strict';

import {
  Body,
  Controller,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
} from '@nestjs/common';
import { AuthorizationService } from './authorization.service';
import { RegistrationDto } from './dto/registration-dto/registration-dto';
import { LoginDto } from './dto/login-dto/login-dto';
import { RefreshDto } from './dto/refresh-dto/refresh-dto';

@Controller('auth')
export class AuthorizationController {
  constructor(private service: AuthorizationService) {}

  @Post('registration')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async registration(
    @Body() registrationDto: RegistrationDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<string> {
    return this.service.registration(registrationDto, ip, userAgent);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async login(
    @Body() loginDto: LoginDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<string> {
    return this.service.login(loginDto, ip, userAgent);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async refresh(
    @Body() refreshDto: RefreshDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ): Promise<string> {
    return this.service.refresh(refreshDto, ip, userAgent);
  }
}
