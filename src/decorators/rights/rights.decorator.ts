'use strict';

import { SetMetadata } from '@nestjs/common';
import { Right } from 'src/common/rights/right.enum';

export const USER_RIGHTS_KEY = 'user_rights';
export const Rights = (...args: Right[]) => SetMetadata(USER_RIGHTS_KEY, args);
