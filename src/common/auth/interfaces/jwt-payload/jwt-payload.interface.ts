'use strict';

export interface JwtPayload {
  iss: string;
  iat: number;
  sub: string;
  aud: {
    userId: string;
    rights: number;
    sessionId: string;
    deviceHash: string;
    mixin: string;
  };
  exp: number;
}
