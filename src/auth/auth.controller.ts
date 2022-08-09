import {
    Body,
    Controller,
    HttpCode,
    Post,
    Req,
    UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { User } from 'src/common/decorators';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtRefreshGuard } from './jwt-refresh.guard';
import { LocalAuthGuard } from './local-auth.guard';
import { JwtPayload, JwtPayloadWithRt } from './types';
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
    @HttpCode(201)
    signup(@Body() user: CreateUserDto): Promise<Tokens> {
        return this.authService.signup(user);
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @HttpCode(202)
    logout(@User() user: JwtPayload) {
        return this.authService.logout(user.sub);
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    refresh(@User() user: JwtPayloadWithRt) {
        return this.authService.refreshTokens(user.sub, user.refreshToken);
    }
}
