'use strict';

import { Injectable } from '@nestjs/common';
import { UserService } from 'src/common/user/user.service';

@Injectable()
export class UserManagerService {
  constructor(private users: UserService) {}

  public async logout(all: boolean = false): Promise<boolean> {
    return true;
  }
}
