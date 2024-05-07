'use strict';

import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from './session.entity';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(Session)
    private readonly repo: Repository<Session>,
  ) {}

  public async save(session: Session): Promise<Session> {
    return this.repo.save(session);
  }

  public async find(id: string): Promise<Session | null> {
    return this.repo.findOneBy({
      id: id,
    });
  }

  public async deleteById(id: string): Promise<any> {
    return this.repo.delete({
      id: id,
    });
  }

  public async deleteByUuid(uuid: string): Promise<any> {
    return this.repo.delete({
      uuid: uuid,
    });
  }
}
