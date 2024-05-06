'use strict';

import { UserBearerGuard } from './user-bearer.guard';

describe('UserBearerGuard', () => {
  it('should be defined', () => {
    expect(new UserBearerGuard()).toBeDefined();
  });
});
