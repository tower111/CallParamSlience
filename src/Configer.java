import java.util.ArrayList;
import java.util.List;
import utils.FuncTypeInterface;
public class Configer {
    public Configer() {
        InitBadFuncName();
        InitDangerCall();
    }
    public ArrayList<String>BadFuncName=new ArrayList<>();
    public boolean TraceOneFStart=true;  //是否追踪一个变量的多次赋值，true为追踪，否则不追踪

    public void InitBadFuncName(){
        BadFuncName.add("__libc_start_main");
    }
//    public List<Integer> func_param=FuncTypeInterface.get_list(0,50);
    public List<Integer> func_param=new ArrayList<Integer>(List.of());   //设置为空表示遇到不确定的函数不会收集其参数
    public int FuncDeep=1;   //向上引用的深度


    public boolean OnlyDanger=true;
    public ArrayList<String>DangerCall=new ArrayList<>();
    public void InitDangerCall(){
        DangerCall.add("system");
        DangerCall.add("strcpy");
        DangerCall.add("strncpy");
        DangerCall.add("memcpy");
        DangerCall.add("memncpy");
        DangerCall.add("sprintf");
        DangerCall.add("snprintf");
//        BadFuncName.add("");

    }

//            new ArrayList<String>();

//    BadFuncName.add("");
}
