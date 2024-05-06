'use strict';

import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  VersionColumn,
} from 'typeorm';

@Entity({
  name: 'users',
})
export class User {
  static IS_ADMIN = 1 << 30;
  static IS_SERVICE = 1 << 29;

  @PrimaryGeneratedColumn('uuid', {
    comment: 'unique user id by uuid',
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

  @Column({
    unique: true,
    nullable: false,
    comment: 'user email',
  })
  email: string;

  @Column({
    unique: true,
    nullable: false,
    comment: 'user login',
  })
  login: string;

  @Column({
    type: 'text',
    nullable: false,
    comment: 'user password hash',
  })
  password: string;

  @Column({
    default: 0,
    nullable: false,
    comment: 'user accesses',
  })
  accesses: number;
}
