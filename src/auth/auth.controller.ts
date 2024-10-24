import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Res,
  UseGuards,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateAuthDto } from "./dto/create-auth.dto";
import { UpdateAuthDto } from "./dto/update-auth.dto";
import { Response } from "express";
import { SignInDto } from "./dto";
import { CookieGetter } from "../common/decorators/cookie_getter.decorator";
import { AccessTokenGuard, RefreshTokenGuard } from "../common/guards";
import { Public } from "../common/decorators";

@UseGuards(AccessTokenGuard)
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post("signup")
  async signup(
    @Body() createAuthDto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.signup(createAuthDto, res);
  }

  @Public()
  @Post("signin")
  async signin(
    @Body() signInDto: SignInDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.signin(signInDto, res);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post("signout")
  async signOut(
    @CookieGetter("refresh_token") refreshToken: string,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.signout(refreshToken, res);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post("refreshtoken")
  async refreshToken(
    @Res({ passthrough: true }) res: Response,
    @CookieGetter("refresh_token") refresh_token: string
  ) {
    return this.authService.refreshTokens(refresh_token, res);
  }

  @Get("get")
  findAll() {
    return this.authService.findAll();
  }

  @Get("get/:id")
  findOne(@Param("id") id: string) {
    return this.authService.findOne(+id);
  }

  @Patch("update/:id")
  update(@Param("id") id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete("delete/:id")
  remove(@Param("id") id: string) {
    return this.authService.remove(+id);
  }
}
