package com.grepp.spring.token.repository

import com.grepp.spring.token.entity.UserBlackList
import org.springframework.data.repository.CrudRepository


interface UserBlackListRepository : CrudRepository<UserBlackList, String>
