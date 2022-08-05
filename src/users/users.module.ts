import { Module } from '@nestjs/common';
import { PrismaClientService } from 'src/prisma-client.service';
import { UsersService } from './users.service';

@Module({
    providers: [UsersService, PrismaClientService],
    exports: [UsersService],
})
export class UsersModule {}
