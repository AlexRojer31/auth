'use strict';

export interface JwtPayload {
  iss: string;
  iat: number;
  sub: string;
  aud: {
    client: string;
    userId: string;
    sessionId: string;
    deviceHash: string;
    mixin: string;
  };
  exp: number;
}
