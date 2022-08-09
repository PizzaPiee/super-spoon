import { Controller, Get, Request, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { JwtPayload } from './auth/types';
import { User } from './common/decorators';

@Controller()
export class AppController {
    @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@User() user: JwtPayload) {
        return user;
    }
}
