package utils;

public class SavePcode {
    public String value_type;
    public String value_value;
    public String pcode;
    public String param1_type;
    public String param1_value;
    public String param2_type;
    public String param2_value;
    public String toString(){
        return value_type+"@@"+value_value+"@@"+pcode+"@@"+param1_type+"@@"+param1_value+"@@"+param2_type+"@@"+param2_value;
    }
}
