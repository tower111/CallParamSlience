package utils;

import jnr.ffi.annotations.Out;

import java.util.ArrayList;
import java.util.List;

public class FuncTypeStruct {

    /*
     * name为指令名
     * type为指令类型 包含：Control，Data，Mem，Func
     * */
    public String name;     //函数名
    public FuncTypeEnum.typeEnum type;   //函数种类
    public List<Integer> in;    //作为函数输入的变量的列表
    public List<Integer> out;   //作为函数输出的变量的列表
    //如果参数数量为变长 如sprintf  in或out列表设置为[0:50]



    public FuncTypeStruct(String N, FuncTypeEnum.typeEnum T, List<Integer> in, List<Integer> out) {
        this.name = N;
        this.type = T;
        this.in=in;
        this.out=out;
    }

}
