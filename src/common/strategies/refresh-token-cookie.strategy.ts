import { ExtractJwt, JwtFromRequestFunction, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtPayload, JwtPayloadWithRefreshToken } from "../types";
import { Request } from "express";

export const cookieExtractor:JwtFromRequestFunction = (req: Request)=> {
  if (req && req.cookies){
    return req.cookies['refresh_token'];
  }
  return null;
}

@Injectable()
export class RefreshTokenCookieStrategy extends PassportStrategy(Strategy,"refresh-jwt") {
  constructor() {
    super({
      jwtFromRequest: cookieExtractor,
      secretOrKey: process.env.REFRESH_TOKEN_KEY,
      passReqToCallback: true,
    });
  }

  async validate(req: Request,payload: JwtPayload): Promise<JwtPayloadWithRefreshToken> {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new ForbiddenException("No refresh token provided");
    }
    return {...payload,refreshToken};
  }
}
