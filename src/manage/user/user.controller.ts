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
import { BearerToken } from 'src/decorators/bearer-token/bearer-token.decorator';
import { BearerGuard } from 'src/guards/bearer/bearer.guard';

@Controller('manage/user')
export class UserController {
  constructor(private service: UserManagerService) {}

  @Post('logout')
  @UseGuards(BearerGuard)
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async logout(@BearerToken() token: string): Promise<boolean> {
    return this.service.logout(token);
  }

  @Post('logout/all')
  @UseGuards(BearerGuard)
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async logoutAll(@BearerToken() token: string): Promise<boolean> {
    return this.service.logout(token, true);
  }
}
