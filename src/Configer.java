import java.util.ArrayList;
import java.util.List;
import utils.FuncTypeInterface;
public class Configer {
    public Configer() {
        InitBadFuncName();
    }
    public ArrayList<String>BadFuncName=new ArrayList<>();
    public boolean TraceOneFStart=false;  //是否追踪一个变量的多次赋值，true为追踪，否则不追踪

    public void InitBadFuncName(){
        BadFuncName.add("__libc_start_main");
    }
//    public List<Integer> func_param=FuncTypeInterface.get_list(0,50);
    public List<Integer> func_param=new ArrayList<Integer>(List.of());   //设置为空表示遇到不确定的函数不会收集其参数

//            new ArrayList<String>();

//    BadFuncName.add("");
}
