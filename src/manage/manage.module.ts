'use strict';

import { Module } from '@nestjs/common';
import { UserController } from './user/user.controller';
import { UserManagerService } from './user/user-manager/user-manager.service';
import { CommonModule } from 'src/common/common.module';

@Module({
  imports: [CommonModule],
  controllers: [UserController],
  providers: [UserManagerService],
})
export class ManageModule {}
