package utils;

public class FuncTypeEnum {
    public enum typeEnum {
        /*
        * Data 为数据流追踪需要追踪
        * Control 为控制流，不一定需要追踪
        * Other 为其他不能确定的用户自定义函数
        * Undefine 用户自定义函数
        * */
        Data,Control,Other,Undefine;
    };

}