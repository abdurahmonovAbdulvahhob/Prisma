import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class CreateAuthDto {
  @IsOptional()
  @IsString()
  readonly name?: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  readonly confirm_password: string;
}
