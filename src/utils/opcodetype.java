package utils;

public class opcodetype {
    public enum typeEnum {
        /*Control：控制指令，判断之后影响程序的执行流，如INT_EQUAL  但是不包括call和BRANCH
        * Data:数据指令，包含数据的计算和转移指令
        *Mem：访问内存的指令，包含LOAD等
        *Func：为函数调用指令，如Call
        * Other：其他指令，这里不关注
        * Brance：分支指令 如BRANCH
        * Direct  :目前不确定，或许有用  INDIRECT
        *   */
        Control, Data, Mem, Func,Other,Brance,Direct;
    };

}
