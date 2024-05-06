'use strict';

import {
  Body,
  Controller,
  Header,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { InfoService } from './info.service';
import { CheckTokenDto } from './dto/check-token-dto/check-token-dto';

@Controller('info')
export class InfoController {
  constructor(private service: InfoService) {}

  @Post('check-token')
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async registration(@Body() dto: CheckTokenDto): Promise<boolean> {
    return this.service.checkToken(dto.accessToken, dto.userAgent, dto.userIp);
  }
}
