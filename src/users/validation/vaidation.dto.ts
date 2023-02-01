import { IsEmail, IsNotEmpty, IsStrongPassword, Length } from 'class-validator';

export class ValidationDto {
  @IsEmail()
  @IsNotEmpty()
  @Length(5, 254)
  userName: string;

  @IsStrongPassword()
  @IsNotEmpty()
  @Length(8, 64)
  password: string;
}
