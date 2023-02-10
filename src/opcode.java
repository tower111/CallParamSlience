import utils.opcodetype;

import java.util.Vector;

public class opcode {
    /*
    * name为指令名
    * type为指令类型 包含：Control，Data，Mem，Func
    * */
    public String name;
    public opcodetype.typeEnum type;

    public opcode(String N,opcodetype.typeEnum T){
        this.name=N;
        this.type=T;
    }
}
