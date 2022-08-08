import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { UsersModule } from 'src/users/users.module';
import { AuthService } from './auth.service';
import { LocalStrategy } from './local.strategy';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { JwtStrategy } from './jwt.strategy';
import { PrismaClientService } from 'src/prisma-client.service';
import { RtStrategy } from './jwt-refresh.strategy';

@Module({
    providers: [
        AuthService,
        LocalStrategy,
        JwtStrategy,
        PrismaClientService,
        RtStrategy,
    ],
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.register({
            secret: jwtConstants.secret,
            signOptions: { expiresIn: '5m' },
        }),
    ],
    controllers: [AuthController],
})
export class AuthModule {}
