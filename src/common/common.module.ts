'use strict';

import { Module } from '@nestjs/common';
import { UserService } from './user/user.service';
import { SessionService } from './session/session.service';
import { GeneratorService } from './generator/generator.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/user.entity';
import { Session } from './session/session.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, Session])],
  providers: [UserService, SessionService, GeneratorService],
  exports: [UserService, SessionService, GeneratorService],
})
export class CommonModule {}
