'use strict';

import { Injectable } from '@nestjs/common';
import { Right } from './right.enum';

@Injectable()
export class RightsService {
  public isService(rights: number): boolean {
    return this.checkRight(rights, Right.Service);
  }

  public isAdmin(rights: number): boolean {
    return this.checkRight(rights, Right.Admin);
  }

  public checkRight(rights: number, right: Right): boolean {
    return (rights & right) > 0;
  }
}
