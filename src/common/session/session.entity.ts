'use strict';

import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  VersionColumn,
} from 'typeorm';

@Entity({
  name: 'sessions',
})
export class Session {
  @PrimaryGeneratedColumn('uuid', {
    comment: 'unique session id by uuid',
  })
  id: string;

  @CreateDateColumn({
    comment: 'created date',
  })
  created: Date;

  @UpdateDateColumn({
    comment: 'updated date',
  })
  updated: Date;

  @VersionColumn({
    comment: 'object version controll',
  })
  version: number;

  @Index()
  @Column({
    nullable: false,
    comment: 'unique user id by uuid',
  })
  uuid: string;

  @Column({
    type: 'text',
    nullable: false,
    comment: 'device hash',
  })
  deviceHash: string;

  @Column({
    nullable: false,
    comment: 'token mixin',
  })
  mixin: string;
}
