'use strict';

import { AbstractBaseBearerGuard } from './abstract-base-bearer.guard';

describe('AbstractBaseBearerGuard', () => {
  it('should be defined', () => {
    expect(
      new (class AbstractBaseBearerGuardTest extends AbstractBaseBearerGuard {})(),
    ).toBeDefined();
  });
});
