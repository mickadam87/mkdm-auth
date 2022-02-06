import { NextFunction, Request, Response } from "express";
import JWT, { JsonWebTokenError, JwtPayload } from "jsonwebtoken";

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
const accessExpDelay = process.env.ACCESS_TOKEN_DELAY;
const refreshExpDelay = process.env.REFRESH_TOKEN_DELAY;

export default class JsonWebTokenAuthenticationMiddleware {
  private static async accessGenerator(payload: object) {
    return JWT.sign(payload, accessTokenSecret, { expiresIn: accessExpDelay });
  }

  private static async refreshGenerator(payload: object) {
    return JWT.sign(payload, refreshTokenSecret, {
      expiresIn: refreshExpDelay,
    });
  }

  static async generateToken(payload: object) {
    let access = this.accessGenerator(payload);
    let refresh = this.refreshGenerator(payload);
    return { access, refresh };
  }

  static async verifier(request: Request, reply: Response, next: NextFunction) {
    const token =
      request.cookies.refresh ||
      request.headers.authorization.split("Bearer ")[0];

    JWT.verify(
      token,
      accessTokenSecret,
      (error: JsonWebTokenError, decoded: JwtPayload) => {
        if (error) {
          return reply.json({ error: "UNAUTHORIZE_REQUEST" });
        }
        next();
      }
    );
  }

  static async refresher(
    request: Request,
    reply: Response,
    next: NextFunction
  ) {
    const token =
      request.cookies.refresh ||
      request.headers.authorization.split("Bearer ")[0];

    JWT.verify(
      token,
      refreshTokenSecret,
      (error: JsonWebTokenError, decoded: JwtPayload) => {
        if (error) {
          return reply.json({ error: "UNAUTHORIZE_REQUEST" });
        }
        const access = this.accessGenerator(decoded);
        reply.status(200).json({ access });
      }
    );
  }
}
