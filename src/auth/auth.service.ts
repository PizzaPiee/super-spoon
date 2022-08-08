import {
    ForbiddenException,
    HttpException,
    HttpStatus,
    Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientService } from 'src/prisma-client.service';
import { Prisma } from '@prisma/client';
import { Tokens } from './types/token.type';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private prisma: PrismaClientService,
    ) {}

    async login(user: any): Promise<Tokens> {
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refreshToken);
        return tokens;
    }

    async signup(data: CreateUserDto): Promise<Tokens> {
        const salt = await bcrypt.genSalt();
        const hash = await bcrypt.hash(data.password, salt);
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: data.email,
                    hash,
                },
            });
            return this.login({ id: user.id, email: user.email });
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

    async logout(id: string) {
        await this.prisma.user.updateMany({
            where: {
                id,
                hashedRt: {
                    not: null,
                },
            },
            data: {
                hashedRt: null,
            },
        });
    }

    async refreshTokens(userId: string, rt: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user) throw new ForbiddenException('Access Denied');

        const rtMatches = await bcrypt.compare(rt, user.hashedRt);
        if (!rtMatches) throw new ForbiddenException('Access Denied');

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refreshToken);
        return tokens;
    }

    async updateRtHash(id: string, rt: string) {
        const salt = await bcrypt.genSalt();
        const hash = await bcrypt.hash(rt, salt);
        await this.prisma.user.update({
            where: {
                id,
            },
            data: {
                hashedRt: hash,
            },
        });
    }

    async validateUser(email: string, plainPassword: string) {
        const user = await this.usersService.findUser(email);
        if (user) {
            const isMatch = bcrypt.compare(plainPassword, user.hash);
            if (isMatch) {
                // strip the hash and hashedRt property from the user object before returning it
                const { hash, hashedRt, ...result } = user;
                return result;
            }
        } else {
            throw new HttpException(
                {
                    status: HttpStatus.UNAUTHORIZED,
                    error: 'there is no user with such email',
                },
                HttpStatus.UNAUTHORIZED,
            );
        }

        return null;
    }

    async getTokens(id: string, email: string): Promise<Tokens> {
        const payload = { email: email, sub: id };
        return {
            accessToken: this.jwtService.sign(payload),
            refreshToken: this.jwtService.sign(payload, { expiresIn: '1d' }),
        };
    }
}
