package utils;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.app.decompiler.ClangToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    public String CallStatement;

    //该变量不会被保存，被用来做检测
    public Map<Integer,ArrayList<ArrayList<ClangToken>>> RealSlience=new HashMap();  //格式 arraylist(Map(index,arrarylist(每个变量的参数切片列表))) 因为函数参数会出现表达式



    public void json_project(ObjectNode funcJsNode){
        funcJsNode.put("binary_path",binary_path);
        funcJsNode.put("Func_name",Func_name);
        funcJsNode.put("Func_address",Func_address);
        funcJsNode.put("fu_inFunc_index",fu_inFunc_index);
        funcJsNode.put("Fu_funcname",Fu_funcname);
        funcJsNode.put("Call_address",Call_address);
        funcJsNode.put("CallBlockAddress",CallBlockAddress);
        funcJsNode.put("num_param",num_param);
        funcJsNode.put("CallStatement",CallStatement);
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
