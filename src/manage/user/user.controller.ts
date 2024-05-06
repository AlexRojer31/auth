'use strict';

import {
  Controller,
  Header,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { UserManagerService } from './user-manager/user-manager.service';
import { UserBearerGuard } from 'src/guards/user-bearer/user-bearer.guard';

@Controller('manage/user')
export class UserController {
  constructor(private service: UserManagerService) {}

  @Post('logout')
  @UseGuards(UserBearerGuard)
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async logout(): Promise<boolean> {
    return this.service.logout();
  }

  @Post('logout/all')
  @UseGuards(UserBearerGuard)
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async logoutAll(): Promise<boolean> {
    return this.service.logout(true);
  }
}
