import { Injectable } from '@nestjs/common';
import { PrismaClientService } from 'src/prisma-client.service';

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaClientService) {}

    async findUser(email: string) {
        return await this.prisma.user.findFirst({
            where: {
                email: email,
            },
        });
    }
}
