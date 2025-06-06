'use strict';

import {
  Body,
  Controller,
  Header,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { InfoService } from './info.service';
import { CheckTokenDto } from './dto/check-token-dto/check-token-dto';
import { Rights } from 'src/decorators/rights/rights.decorator';
import { Right } from 'src/common/rights/right.enum';
import { BearerGuard } from 'src/guards/bearer/bearer.guard';

@Controller('info')
export class InfoController {
  constructor(private service: InfoService) {}

  @Post('check-token')
  @UseGuards(BearerGuard)
  @Rights(Right.Service)
  @HttpCode(HttpStatus.OK)
  @Header('Content-Type', 'application/json; charset=utf-8')
  public async checkToken(@Body() dto: CheckTokenDto): Promise<boolean> {
    return this.service.checkToken(dto.accessToken, dto.userAgent, dto.userIp);
  }
}
