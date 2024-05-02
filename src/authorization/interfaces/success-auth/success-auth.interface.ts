'use strict';

export interface SuccessAuth {
  id: string;
  accessToken: string;
  accessTokenExpire: number;
  refreshToken: string;
  refreshTokenExpire: number;
}
