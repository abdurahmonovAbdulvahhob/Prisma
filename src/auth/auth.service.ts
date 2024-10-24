import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { CreateAuthDto, SignInDto, UpdateAuthDto } from "./dto";
import * as bcrypt from "bcrypt";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../prisma/prisma.service";
import { Response } from "express";
import { User } from "@prisma/client";
import { JwtPayload, ResUser, Tokens } from "../common/types";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async generateTokens(user: User): Promise<Tokens> {
    const payload:JwtPayload = {
      id: user.id,
      email: user.email,
    };

    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return { access_token, refresh_token };
  }

  async updateRefreshToken(userId: number, refresh_token: string) {
    const hashedRefreshToken = await bcrypt.hash(refresh_token, 7);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    });
  }

  async signup(createAuthDto: CreateAuthDto, res: Response): Promise<ResUser> {
    const candidate = await this.prismaService.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });

    if (candidate) {
      throw new BadRequestException("Email already exists");
    }

    if (createAuthDto.password !== createAuthDto.confirm_password) {
      throw new BadRequestException("Password does not match");
    }
    const hashedPassword = await bcrypt.hash(createAuthDto.password, 10);

    const newUser = await this.prismaService.user.create({
      data: {
        name: createAuthDto.name,
        email: createAuthDto.email,
        hashedPassword,
      },
    });

    const tokens = await this.generateTokens(newUser);
    await this.updateRefreshToken(newUser.id, tokens.refresh_token);
    res.cookie("refresh_token", tokens.refresh_token, {
      maxAge: +process.env.COOKIE_TIME,
      httpOnly: true,
    });

    return { id: newUser.id, access_token: tokens.access_token };
  }

  async signin(signInDto: SignInDto,res: Response): Promise<ResUser> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: signInDto.email,
      },
    });

    if (!user) {
      throw new BadRequestException("Invalid email or password");
    }
    const valid_password = await bcrypt.compare(
      signInDto.password,
      user.hashedPassword
    );
    if (!valid_password) {
      throw new BadRequestException("Invalid email or password");
    }
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    res.cookie("refresh_token", tokens.refresh_token, {
      maxAge: +process.env.COOKIE_TIME,
      httpOnly: true,
    });
    return {
      id:user.id,
      access_token: tokens.access_token,
    };
  }

  async signout(refreshToken: string, res: Response) {
    const payload = await this.jwtService.verifyAsync(refreshToken, {
      secret: process.env.REFRESH_TOKEN_KEY,
    });

    const user = await this.prismaService.user.findUnique({
      where: { id: payload.id,hashedRefreshToken: {not: null} },
    });
    if (!user) {
      throw new BadRequestException("User not found");
    }

    await this.prismaService.user.update({
      where: { id: user.id },
      data: { hashedRefreshToken: null },
    });

    res.clearCookie("refresh_token");

    return {
      message: "User successfully logouted",
    };
  }

  async refreshTokens(refresh_token: string, res: Response): Promise<ResUser> {
    try {
      const payload:JwtPayload = await this.jwtService.verifyAsync(refresh_token, {
        secret: process.env.REFRESH_TOKEN_KEY,
      });

      const user = await this.prismaService.user.findUnique({
        where: { id: payload.id },
      });
      if (!user) {
        throw new UnauthorizedException("User not found");
      }

      const valid_refresh_token = await bcrypt.compare(
        refresh_token,
        user.hashedRefreshToken
      );
      if (!valid_refresh_token) {
        throw new UnauthorizedException("Unauthorized user");
      }

      const tokens = await this.generateTokens(user);

      await this.updateRefreshToken(user.id, tokens.refresh_token);

      res.cookie("refresh_token", tokens.refresh_token, {
        httpOnly: true,
        maxAge: +process.env.COOKIE_TIME,
      });

      return {
        access_token: tokens.access_token,
        id:user.id
      };
    } catch (error) {
      console.log(error);
      throw new BadRequestException("Expired token");
    }
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
