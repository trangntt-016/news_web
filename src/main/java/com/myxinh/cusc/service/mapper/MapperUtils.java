package com.myxinh.cusc.service.mapper;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MapperUtils<entity,T> {

    @Autowired
    ModelMapper modelMapper;

    public MapperUtils(){};

    public T convert(entity entity,Class<T> type){
        return modelMapper.map(entity,type);
    }

}
