package Check;

import ghidra.app.decompiler.ClangToken;
import utils.FuncTypeStruct;
import utils.FuncUicorn;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Map;

public class CheckStackOverflow {
    public FuncUicorn fu;
    public boolean isVul=false;
    public CheckStackOverflow(FuncUicorn fu){
        this.fu=fu;
        switch (fu.Fu_funcname){
            case "sprintf":{
                isVul=sprintf();
                break;
            }
            default:
                break;
        }
    }

    public boolean sprintf(){
        assert fu.Fu_funcname.equals("sprintf");
        ArrayList slience_sources = (ArrayList)fu.RealSlience.get(1);
        if (slience_sources.size()==0)return false;
        ArrayList<ClangToken> var_slience = (ArrayList<ClangToken>)(slience_sources.get(0));
        if (var_slience.size()==0) return false;
        ClangToken lasttoken=var_slience.get(var_slience.size()-1);
//        for(ClangToken slience:(ClangToken[]) slience_sources.get(0)){
//            slience.
//        }
        return true;
    }



}
