'use strict';

import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly repo: Repository<User>,
  ) {}

  public async findByEmail(email: string): Promise<User | null> {
    return this.repo.findOneBy({
      email: email,
    });
  }

  public async findByLogin(login: string): Promise<User | null> {
    return this.repo.findOneBy({
      login: login,
    });
  }

  public async save(user: User): Promise<User> {
    return this.repo.save(user);
  }

  public async checkEmail(email: string): Promise<boolean> {
    return Boolean(await this.findByEmail(email));
  }

  public async checkLogin(login: string): Promise<boolean> {
    return Boolean(await this.findByLogin(login));
  }

  public async find(id: string): Promise<User | null> {
    return this.repo.findOneBy({
      id: id,
    });
  }
}
