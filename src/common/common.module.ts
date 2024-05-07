'use strict';

import { Module } from '@nestjs/common';
import { UserService } from './user/user.service';
import { SessionService } from './session/session.service';
import { GeneratorService } from './generator/generator.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/user.entity';
import { Session } from './session/session.entity';
import { AuthService } from './auth/auth.service';
import { JwtModule } from '@nestjs/jwt';
import { RightsService } from './rights/rights.service';

@Module({
  imports: [TypeOrmModule.forFeature([User, Session]), JwtModule],
  providers: [
    UserService,
    SessionService,
    GeneratorService,
    AuthService,
    RightsService,
  ],
  exports: [
    UserService,
    SessionService,
    GeneratorService,
    AuthService,
    RightsService,
  ],
})
export class CommonModule {}
