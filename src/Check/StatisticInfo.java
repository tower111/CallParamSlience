package Check;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableDecl;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.program.model.data.*;
import utils.FuncUicorn;
//import com.fasterxml.jackson.core.JSON
//import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class StatisticInfo {
    public FuncUicorn fu;

    public StatisticInfo(FuncUicorn fu) {
        this.fu = fu;
        GetInfo();
    }

    public int number_param = 0;
    public int number_call_param = 0;
    public int number_var = 0;
    public int number_call = 0;   //函数数量
    public int number_const = 0;
    public ArrayList<String> const_list = new ArrayList<String>();
    public int Slience_len = 0;
    public ArrayList<Map<String, Integer>> ArrayMap = new ArrayList<Map<String, Integer>>();//数组空间大小  变量名：变量空间大小
    public ArrayList<Map<String, String>> varMap = new ArrayList<Map<String, String>>(); //普通变量空间   变量名：变量类型

    public void json_project(ObjectNode funcJsNode) {
        funcJsNode.put("num_param", number_param);
        funcJsNode.put("number_call_param", number_call_param);
        funcJsNode.put("number_var", number_var);
        funcJsNode.put("number_call", number_call);
        funcJsNode.put("number_const", number_const);
//        funcJsNode.put("const_list", const_list.toString());
        funcJsNode.put("Slience_len", Slience_len);
//        funcJsNode.put("ArrayMap", ArrayMap.toString());
        funcJsNode.put("varMap", varMap.toString());



//        ObjectNode funcJsNode = mapper.createObjectNode();
        ArrayNode Aj = funcJsNode.putArray("const_list");
        for (String value : const_list) {
            Aj.add(value);
        }
        ArrayNode Am = funcJsNode.putArray("ArrayMap");
        for(Map value: ArrayMap){
            ObjectMapper objectMapper = new ObjectMapper();
            ObjectNode child = objectMapper.createObjectNode();
            for(Object key:value.keySet()){
                child.put((String) key, (Integer) value.get(key));
            }
            Am.add(child);
        }
        ArrayNode vm = funcJsNode.putArray("varMap");
        for(Map value: varMap){
            ObjectMapper objectMapper = new ObjectMapper();
            ObjectNode child = objectMapper.createObjectNode();
            for(Object key:value.keySet()){
                child.put((String) key, (String) value.get(key));
            }
            vm.add(child);
        }
    }



    public ObjectNode toJson() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode funcJsNode= mapper.createObjectNode();
        this.json_project(funcJsNode);
        return funcJsNode;
    }

    public void GetInfo() {
        for(Integer key:fu.RealSlience.keySet()){//每个函数
            for(ArrayList<ClangToken> cts: fu.RealSlience.get(key)){//每个参数

                number_call_param+=1;
                for(ClangToken ct:cts){//每个变量
                    if(ct instanceof ClangVariableToken) {
                        if (ct.Parent() instanceof ClangVariableDecl) {
                            number_var += 1; //定义变量
                            DataType dtype = ((ClangVariableDecl) ct.Parent()).getDataType();
                            if (dtype instanceof ArrayDataType) {//是数组
                                Integer dd = ((ArrayDataType) dtype).getNumElements();
                                Map<String, Integer> mp = new HashMap<String, Integer>();
                                mp.put(ct.toString(), dd);
                                ArrayMap.add(mp);
                            }

                            if (ct.getSyntaxType() == ClangToken.PARAMETER_COLOR) {
                                number_param += 1;
                            }
                            Class<? extends DataType> dcalss = dtype.getClass();
                            Map<String, String> mp = new HashMap<>();
                            mp.put(ct.toString(), dcalss.toString());
                            varMap.add(mp);
//                            int aa;
//                            aa = 0;

                        }

                    }
                    if(ct.getSyntaxType()==ClangToken.FUNCTION_COLOR) number_call+=1;//调用函数
                    if(ct.getSyntaxType()==ClangToken.CONST_COLOR){
                        number_const+=1;
                        const_list.add(ct.toString());
                    }
                    Slience_len+=1;

                }
            }
        }

    }
}

