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
    default: false,
    nullable: false,
    comment: 'is this user admin',
  })
  isAdmin: boolean;

  @Column({
    default: false,
    nullable: false,
    comment: 'is this user service',
  })
  isService: boolean;

  @Column({
    default: 0,
    nullable: false,
    comment: 'user accesses',
  })
  accesses: number;
}
