import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LocalAuthGuard } from './local-auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @UseGuards(LocalAuthGuard)
    @Post('login')
    login(@Body() user) {
        return this.authService.login(user);
    }

    @Post('signup')
    signup(@Body() user: CreateUserDto) {
        return this.authService.signup(user);
    }
}
