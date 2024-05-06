'use strict';

import { ServiceBearerGuard } from './service-bearer.guard';

describe('ServiceBearerGuard', () => {
  it('should be defined', () => {
    expect(new ServiceBearerGuard()).toBeDefined();
  });
});
