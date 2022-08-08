import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtRefreshGuard } from './jwt-refresh.guard';
import { LocalAuthGuard } from './local-auth.guard';
import { JwtPayloadWithRt } from './types';
import { Tokens } from './types/token.type';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @UseGuards(LocalAuthGuard)
    @Post('login')
    login(@Req() req): Promise<Tokens> {
        return this.authService.login(req.user);
    }

    @Post('signup')
    signup(@Body() user: CreateUserDto): Promise<Tokens> {
        return this.authService.signup(user);
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    logout(@Req() req) {
        console.log(req.user.userId);
        return this.authService.logout(req.user.userId);
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    refresh(@Req() req) {
        const user: JwtPayloadWithRt = req.user;
        console.log(user);
        return this.authService.refreshTokens(user.sub, user.refreshToken);
    }
}
