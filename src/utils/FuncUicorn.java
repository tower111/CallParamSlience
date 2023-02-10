package utils;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

public class FuncUicorn {
    public  String binary_path;
    public String Func_name;
    public String fu_inFunc_index;
    public String Fu_funcname;
    public String num_param;
    public String Call_address;
    public String Func_address;
    public String CallBlockAddress;
    public List<List<String>> Fu_Pcode;
    public List<List<String>> Fu_Ccode;



    public void json_project(ObjectNode funcJsNode){
        funcJsNode.put("binary_path",binary_path);
        funcJsNode.put("Func_name",Func_name);
        funcJsNode.put("Func_address",Func_address);
        funcJsNode.put("fu_inFunc_index",fu_inFunc_index);
        funcJsNode.put("Fu_funcname",Fu_funcname);
        funcJsNode.put("Call_address",Call_address);
        funcJsNode.put("CallBlockAddress",CallBlockAddress);
        funcJsNode.put("num_param",num_param);
        ArrayNode fu_pcode = funcJsNode.putArray("Fu_Pcode");
        int param_index = 0;
        for(List<String> value:Fu_Pcode){
           ObjectNode Lpcode =fu_pcode.addObject();
            ArrayNode lpcode=Lpcode.putArray("param"+String.valueOf(param_index));
            for(String pcode:value){
                lpcode.add(pcode);
            }
            param_index+=1;
        }
        param_index = 0;
        ArrayNode fu_ccode = funcJsNode.putArray("Fu_Ccode");
        for(List<String> value:Fu_Ccode){
            ObjectNode Lpcode =fu_ccode.addObject();
            ArrayNode lpcode=Lpcode.putArray("param"+String.valueOf(param_index));
            for(String pcode:value){
                lpcode.add(pcode);
            }
            param_index+=1;
        }

    }


}
