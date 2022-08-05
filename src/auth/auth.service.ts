import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientService } from 'src/prisma-client.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private prisma: PrismaClientService,
    ) {}

    async validateUser(email: string, plainPassword: string) {
        const user = await this.usersService.findUser(email);
        if (user) {
            const isMatch = bcrypt.compare(plainPassword, user.password);
            if (isMatch) {
                // strip the password property from the user object before returning it
                const { password, ...result } = user;
                return result;
            }
        }

        return null;
    }

    async login(user: any) {
        const payload = { email: user.email, sub: user.id };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }

    async signup(user: CreateUserDto) {
        const salt = await bcrypt.genSalt();
        const password = await bcrypt.hash(user.password, salt);
        try {
            await this.prisma.user.create({
                data: { ...user, password },
            });
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError) {
                if (e.code === 'P2002') {
                    throw new HttpException(
                        {
                            status: HttpStatus.FORBIDDEN,
                            error: 'new user cannot be created with this email',
                        },
                        HttpStatus.FORBIDDEN,
                    );
                }
            }
        }
    }
}
