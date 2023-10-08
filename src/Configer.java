import java.util.ArrayList;
import java.util.List;
import utils.FuncTypeInterface;
public class Configer {
    public Configer() {
        InitBadFuncName();
        InitDangerCall();
        InitDangerAdderss();
    }
    public ArrayList<String>BadFuncName=new ArrayList<>();
    public boolean TraceOneFStart=true;  //是否追踪一个变量的多次赋值，true为追踪，否则不追踪

    public void InitBadFuncName(){
        BadFuncName.add("__libc_start_main");
    }
//    public List<Integer> func_param=FuncTypeInterface.get_list(0,50);
    public List<Integer> func_param=new ArrayList<Integer>(List.of());   //设置为空表示遇到不确定的函数不会收集其参数
    public int FuncDeep=2;   //向上引用的深度
    public int MaxInst=100;//列表中最多token数

///Applications/ghidra_10.1.4_PUBLIC/output aa -scriptPath /Applications/ghidra_10.1.4_PUBLIC/my_script/src -postScript Comfu_function.java -import  /Applications/ghidra_10.1.4_PUBLIC/my_script/out/input  -overwrite
    public boolean EnableDangerFunc=true;//仅收集危险函数
    public ArrayList<String>DangerCall=new ArrayList<>();
    public void InitDangerCall(){
        DangerCall.add("system");
        DangerCall.add("strcpy");
        DangerCall.add("strncpy");
        DangerCall.add("memcpy");
        DangerCall.add("memncpy");
        DangerCall.add("sprintf");
        DangerCall.add("snprintf");
        DangerCall.add("sscanf");
//        DangerCall.add("xmldbc_ephp");
//        BadFuncName.add("");
    }
    public String[]  DangerString={"cmd","exec","system"};
    public ArrayList<String>DangerAddr=new ArrayList<>();
    public String[] BadDangerCall={"pcre_exec"};  //可能被误认为危险函数的一些函数  pcre_exec用于正则匹配
    public void InitDangerAdderss(){
        //可以自定义一个地址作为危险地址，可以减少分析工作量
//        DangerAddr.add();
    }


//            new ArrayList<String>();

//    BadFuncName.add("");
}
