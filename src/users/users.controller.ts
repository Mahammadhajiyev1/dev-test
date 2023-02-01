import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Request,
  ValidationPipe,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AuthenticatedGuard } from 'src/auth/authenticated.guard';
import { LocalAuthGuard } from 'src/auth/local.auth.guard';
import { UsersService } from './users.service';
import { ValidationDto } from './validation/vaidation.dto';
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  //signup
  @Post('/signup')
  async addUser(@Body(new ValidationPipe()) validationDto: ValidationDto) {
    const { password, userName } = validationDto;
    const saltOrRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltOrRounds);
    const result = await this.usersService.insertUser(userName, hashedPassword);
    return {
      msg: 'User successfully registered',
      userId: result.id,
      userName: result.username,
    };
  }
  //Post / Login
  @UseGuards(LocalAuthGuard)
  @Post('/login')
  login(@Request() req): any {
    return { User: req.user, msg: 'User logged in' };
  }
  //Get / protected
  @UseGuards(AuthenticatedGuard)
  @Get('/protected')
  getHello(@Request() req): string {
    return req.user;
  }
}
