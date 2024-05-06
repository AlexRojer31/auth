'use strict';

import { Module } from '@nestjs/common';
import { InfoController } from './info.controller';
import { InfoService } from './info.service';
import { JwtModule } from '@nestjs/jwt';
import { CommonModule } from 'src/common/common.module';

@Module({
  imports: [JwtModule, CommonModule],
  controllers: [InfoController],
  providers: [InfoService],
})
export class InfoModule {}
