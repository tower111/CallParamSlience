package utils;

//import com.sun.java.util.jar.pack.FixedList;
//import jdk.internal.jimage.ImageStrings;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FuncTypeInterface {
    //所追踪变量为函数的in，只需要追踪in
    //所追踪变量为函数的out，则需要追踪变量的in和out
    //  new ArrayList<>(Arrays.asList("1", "2", "3")   new ArrayList<Integer>(Arrays.asList(1, 2, 3))
    public FuncTypeStruct strcpy = new FuncTypeStruct("strcpy", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1)),new ArrayList<Integer>(List.of(0)));
    public FuncTypeStruct strncpy = new FuncTypeStruct("strncpy", FuncTypeEnum.typeEnum.Control, new ArrayList<Integer>(List.of(0,1,2)), new ArrayList<Integer>(List.of(0)));

    public FuncTypeStruct snprintf = new FuncTypeStruct("snprintf", FuncTypeEnum.typeEnum.Data,get_list(0,50),new ArrayList<Integer>(List.of(0)) );//常量被认为是in，方便追踪
    public FuncTypeStruct sprintf = new FuncTypeStruct("sprintf", FuncTypeEnum.typeEnum.Data,  get_list(0,50),new ArrayList<Integer>(List.of(0)));

    public FuncTypeStruct strstr = new FuncTypeStruct("strstr", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1)), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct fclose = new FuncTypeStruct("fclose", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0)), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct fopen = new FuncTypeStruct("fopen", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1)), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct memset = new FuncTypeStruct("memset", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1,2)), new ArrayList<Integer>(List.of(0)));
    public FuncTypeStruct system = new FuncTypeStruct("system", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0)), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct  fgets = new FuncTypeStruct("fgets", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1,2)), new ArrayList<Integer>(List.of(0)));
    public FuncTypeStruct  atoi = new FuncTypeStruct("atoi", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0)), new ArrayList<Integer>(List.of()));
//    public FuncTypeStruct  syslog = new FuncTypeStruct("syslog", FuncTypeEnum.typeEnum.Data, List.of(1,2), List.of(0));
    public FuncTypeStruct  fprintf = new FuncTypeStruct("fprintf", FuncTypeEnum.typeEnum.Data, get_list(0,50), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct  memcpy = new FuncTypeStruct("memcpy", FuncTypeEnum.typeEnum.Data, new ArrayList<Integer>(List.of(0,1,2)), new ArrayList<Integer>(List.of(0)));


    public FuncTypeStruct strncmp = new FuncTypeStruct("strncmp", FuncTypeEnum.typeEnum.Control, new ArrayList<Integer>(List.of(0,1,2)), new ArrayList<Integer>(List.of()));
    public FuncTypeStruct strcmp = new FuncTypeStruct("strcmp", FuncTypeEnum.typeEnum.Control, new ArrayList<Integer>(List.of(0,1)), new ArrayList<Integer>(List.of()));

    public FuncTypeStruct strcasecmp = new FuncTypeStruct("strcasecmp", FuncTypeEnum.typeEnum.Control, new ArrayList<Integer>(List.of(0,1)), new ArrayList<Integer>(List.of()));


    public static FuncTypeStruct getClass(String mnemonic) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        Class<?> clazz = Class.forName("utils.FuncTypeInterface");
        Field[] fieldList = clazz.getDeclaredFields();
        Object obj = clazz.newInstance();
        for (Field field : fieldList) {
            if (mnemonic.equals((field.getName())))
                return (FuncTypeStruct) field.get(obj);
        }
        return null;
    }
    public static   List<Integer> get_list(int from,int to){
        List<Integer> list = new ArrayList<Integer>();
        for(int i=from;i<to;i++){
            list.add(i);
        }
        return list;
    }
}

