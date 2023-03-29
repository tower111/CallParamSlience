//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 
///Applications/ghidra_10.1.4_PUBLIC/output aa -scriptPath /Applications/ghidra_10.1.4_PUBLIC/my_script/src -preScript Comfu_function.java -import  /Users/guosiyu/Desktop/tower/ctf/iot/ciscoRV16/mini_httpd_patched
import Check.StatisticInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.app.decompiler.*;
//import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.util.MD5Utilities;
import utils.DecemplierUtilsMe;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import utils.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import static ghidra.app.decompiler.ClangToken.*;


public class Comfu_function extends GhidraScript {
    long startTime=System.currentTimeMillis();
    public Configer config=new Configer();
    //    private DecompInterface decompInterface=null;
    private FU_result function_unicons = new FU_result();
    public Map FuncDecompliet= new HashMap();

    private List<ClangNode> cnodeList = new ArrayList<ClangNode>();
    private FuncTypeInterface functype=new FuncTypeInterface();
    public ArrayList<ClangToken> source_slience = new ArrayList<>();
    public List<String> source_slience_PcodeString=new ArrayList<>();
    public List<String > source_slience_CcodeString=new ArrayList<>();
    public Func funcinfo=new Func();
    public DecompInterface ifc=null;

    Map chroot_map=new HashMap();   //func_entrypoint:chroot
    public int FuncDeep=0;
    private DecemplierUtilsMe DecompilerUtilsMe;

    public void run() throws Exception {
        String binary_path = currentProgram.getExecutablePath();
        String Md5 = currentProgram.getExecutableMD5();
//        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true); // True means 'forward'
//        Listing listing = currentProgram.getListing();
        DecompileOptions options = new DecompileOptions();
        ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.openProgram(getCurrentProgram());
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        ObjectNode root_slience = mapper.createObjectNode();

//        Map binary_indexed= new HashMap();
        List<Function> passed=new ArrayList<>();
        List<FuncUicorn> FU_silence_list=new ArrayList<>();
        println(binary_path.toString());
        for (Function func : funcs) {
            boolean thunk = func.isThunk();
            boolean external = func.isExternal();
//            func.toString()
            if(thunk){
                passed.add(func);
                continue;
            }
            funcinfo.func=func;
            Map fu_inFunc_index_dict=new HashMap();


            if(true){
//            if (func.getName().equals("FUN_0001e22c")) { //出问题地址 FUN_00012944   FUN_00012944
//                printf("Function: %s @ 0x%s", func.getName(), func.getEntryPoint());
                Address FuncAddres = func.getEntryPoint();
                DecompileResults res = ifc.decompileFunction(func, 60, monitor);

                ClangTokenGroup chroot = res.getCCodeMarkup();
                if (!chroot_map.containsKey(FuncAddres))
                    chroot_map.put(FuncAddres,chroot);
                this.cnodeList=new ArrayList<>();
                getClangNode(chroot);
//                print(this.cnodeList.toString());
//                HighFunction high = res.getHighFunction();
//                Iterator<PcodeOpAST> opiter = high.getPcodeOps();
//                while (opiter.hasNext())
                for(ClangNode iterToken:this.cnodeList){
//                    PcodeOpAST op = opiter.next();
//                    printf("%s\n", op.toString());
                    if((iterToken instanceof ClangFuncNameToken)&!(iterToken.Parent() instanceof ClangFuncProto))//是函数调用
//                    if (op.getMnemonic().equals("CALL"))
                    {
                        assert ((ClangFuncNameToken) iterToken).getPcodeOp().getOpcode()==PcodeOp.CALL;
                        Address CallAddress = ((ClangFuncNameToken) iterToken).Parent().getMaxAddress();
//                        if (!CallAddress.toString().equals("000146a4"))continue;
                        Address CallBlockAddress=((ClangFuncNameToken) iterToken).getPcodeOp().getParent().getStart();
                        assert iterToken.Parent().getMaxAddress()==iterToken.Parent().getMinAddress();
                        ObjectNode funcJsNode= mapper.createObjectNode();
                        FuncUicorn FU_silence =new FuncUicorn();
//                        Varnode[] inputs = op.getInputs();
                        assert iterToken.Parent() instanceof ClangStatement;
                        ClangStatement call_statement = (ClangStatement) iterToken.Parent();

                        String call_name=iterToken.toString();
                        var calleefunc= getGlobalFunctions(call_name);
                        for(Function f:calleefunc){//所有用户自定义函数设置为统一名字
                            if (f.isThunk() | f.isExternal())continue;
                            call_name="USERFUNC";
                        }
                        if(config.BadFuncName.contains(call_name) ) continue;
                        if(!config.DangerCall.contains(call_name)&& !config.OnlyDanger) continue;
//                        Address call_addr = inputs[0].getAddress();
//                        Function called_func = fm.getFunctionAt(call_addr);
//                        String call_name = called_func.getName();
//                        System.out.println("called function " + call_name);
//                        if(!call_name.equals("SSL_CTX_use_certificate_chain_file"))continue;
                        if(fu_inFunc_index_dict.containsKey(call_name)){
                            int num = (int) fu_inFunc_index_dict.get(call_name);
                            num+=1;
                            fu_inFunc_index_dict.put(call_name,num);
                        }
                        else{
                            fu_inFunc_index_dict.put(call_name,0);
                        }
//                        if (!Objects.equals(called_func.getName(), "system")) {
//                            continue;
//                        }
//                        Varnode[] params = Arrays.copyOfRange(inputs, 1, inputs.length);
                        int param_index = 0;
                        Integer real_param_index = 0;
                        List<List<String>> Fu_Pcode_slience=new ArrayList<>();
                        List<List<String>> Fu_Ccode_slience=new ArrayList<>();
                        boolean equal_flag=contine_equal(call_statement);
                        boolean equaled=false;
                        Map one_slience=new HashMap<>();
                        for (int ichild=0 ;ichild< call_statement.numChildren();ichild++) {//每个参数
//                            HighVariable h = node.getHigh();


//                            Set<Varnode> bs = DecompilerUtils.getBackwardSlice(node);
//                            System.out.println("getBackwardSlice: " + bs);
//                            Set<PcodeOp> aa = DecompilerUtils.getBackwardSliceToPCodeOps(node);
//                            System.out.println("getBackwardSliceToPCodeOps: " + aa);
//                            for (Varnode no : bs) {
//                                HighVariable nh = no.getHigh();
//                                System.out.println(nh.getName());
//                            }
                            this.source_slience = new ArrayList<>();
//                            Address addr = node.getPCAddress();
//                            List<ClangToken> tokens = DecompilerUtils.getTokens(chroot, addr);//一个语句的所有token
                            ClangNode token_CallParam  = call_statement.Child(ichild);
                            if (token_CallParam.toString().equals(","))real_param_index+=1;
                            if (!equal_flag)//函数调用没有等号，即所有变量都是参数
                            {
                                if (token_CallParam instanceof ClangVariableToken){
                                    FuncDeep=0;
                                    this.source_slience.add((ClangToken)token_CallParam);
                                    SourceSlience((ClangToken) token_CallParam, chroot,funcinfo,true);
                                    param_index += 1;
                                }
                            }
                            else {
                                    if (token_CallParam.toString().equals("="))
                                        equaled = true;//当前token在等号之后
                                    if (equaled) {//等号之后的变量
                                        if (token_CallParam instanceof ClangVariableToken) {
                                            this.source_slience.add((ClangToken)token_CallParam);
                                            FuncDeep=0;
                                            SourceSlience((ClangToken) token_CallParam, chroot,funcinfo,true);
                                            param_index += 1;
                                        }
                                    }
                                }
                            if(this.source_slience.size()==0)
                                continue;
//                            System.out.println("param index: " + param_index);
                            if (one_slience.containsKey(real_param_index)){
                                ((ArrayList<ArrayList<ClangToken>>)one_slience.get(real_param_index)).add(source_slience);
                            }else{
                                ArrayList<ArrayList<ClangToken>> tmp_var = new ArrayList<ArrayList<ClangToken>>();
                                tmp_var.add(source_slience);
                                one_slience.put(real_param_index, tmp_var);
                            }
                            source_slience_PcodeString=new ArrayList<>();
                            source_slience_CcodeString=new ArrayList<>();
                            for(ClangToken token:this.source_slience) {
                                if (token.Parent() instanceof ClangVariableDecl) {//定义变量
                                    ClangNode defVarTokenGroup = token.Parent();
                                    for (int i = 0; i < defVarTokenGroup.numChildren(); i++) {
                                        ClangToken tmpToken = (ClangToken) defVarTokenGroup.Child(i);
                                        if (tmpToken.getSyntaxType() == CONST_COLOR) {

                                            source_slience_PcodeString.add(tmpToken.toString());
                                        }
                                    }
//                                    if (!source_slience_CcodeString.contains(token.toString()))
                                    source_slience_CcodeString.add(defVarTokenGroup.toString());



                                } else if (token.Parent() instanceof ClangFuncProto) {//定义函数
                                    source_slience_CcodeString.add(token.toString());
                                }else if(token.getSyntaxType()==CONST_COLOR){//常量
                                    source_slience_PcodeString.add(token.toString());
                                    source_slience_CcodeString.add(token.toString());
                                }
                                else if(token.Parent() instanceof ClangStatement&& token.getPcodeOp()==null){//正常指令,包含定义变量的赋值
                                    source_slience_PcodeString.add(token.toString());
                                    source_slience_CcodeString.add(token.Parent().toString());
                                }
                                else if(token.Parent() instanceof ClangStatement&& token.getPcodeOp()!=null){//正常指令
                                    source_slience_PcodeString.add(PcodeToString(token.getPcodeOp(),fm));
                                    source_slience_CcodeString.add(token.Parent().toString());
                                }
                                else {//if(var>1)
                                    source_slience_PcodeString.add(PcodeToString(token.getPcodeOp(),fm));
//                                    source_slience_CcodeString.add(token.Parent().toString());
                                }
                            }
//                            Set<String> SetFu_Pcode_slience = new HashSet<>(source_slience_PcodeString);
//                            Set<String> SetFu_Ccode_slience = new HashSet<>(source_slience_CcodeString);
                            List<String> list_1 = new ArrayList<>(source_slience_PcodeString);
                            List<String> list_2 = new ArrayList<>(source_slience_CcodeString);
//                            List<String> list_2=new ArrayList<>();
//                            for(String l :source_slience_CcodeString)
                            Fu_Pcode_slience.add(list_1);
                            Fu_Ccode_slience.add(list_2);
                        }//一个函数联合体结束

                        FU_silence.RealSlience=one_slience;
                        FU_silence.binary_path=binary_path;
                        FU_silence.Fu_funcname=call_name;
                        FU_silence.CallStatement=call_statement.toString();
                        FU_silence.Call_address=CallAddress.toString();
                        FU_silence.fu_inFunc_index= String.valueOf(fu_inFunc_index_dict.get(call_name));
                        FU_silence.Func_name=func.getName();
                        FU_silence.Func_address=FuncAddres.toString();
                        FU_silence.Fu_Pcode=Fu_Pcode_slience;
                        FU_silence.Fu_Ccode=Fu_Ccode_slience;
                        FU_silence.CallBlockAddress=CallBlockAddress.toString();
                        FU_silence.num_param=String.valueOf(real_param_index);
                        FU_silence.json_project(funcJsNode);
//                        CheckStackOverflow checker=new CheckStackOverflow(FU_silence);
                        StatisticInfo si= new StatisticInfo(FU_silence);
                        ObjectNode siJson = si.toJson();
                        assert param_index==Fu_Ccode_slience.size();
                        if (param_index!=0) {
                            root_slience.set(FU_silence.Func_name + "@@" + FU_silence.Fu_funcname + "@@" + FU_silence.fu_inFunc_index, funcJsNode);
                            root.set(FU_silence.Func_address+"@@"+FU_silence.Func_name + "@@" + FU_silence.Fu_funcname + "@@" + FU_silence.fu_inFunc_index, siJson);
                        }
                    }

                }

//                //原始pcode，函数调用不存在参数
//                AddressSetView func_body = func.getBody();
//                InstructionIterator opiter = listing.getInstructions(func_body, true);
//                for(Instruction inst:opiter){
//                    if (func.getName().equals("FUN_00011fa0")) {
//                        PcodeOp[] raw_pcode = inst.getPcode();
//                        printf("dsm %s  \n ", inst);
//                        for (PcodeOp op : raw_pcode) {
//                            printf("pcode %s  , opcode %s", op, op.getMnemonic());
//                            if (op.getMnemonic().equals("CALL")) {
//                                Varnode[] inputs = op.getInputs();
//                                Address call_addr = inputs[0].getAddress();
//                                Varnode[] args = Arrays.copyOfRange(inputs, 1, inputs.length);
//                                for (Varnode arg : args) {
//                                    Set<Varnode> bs = DecompilerUtils.getBackwardSlice(arg);
//                                    printf("Backward Slice: %s", bs);
//                                }
//                            }
//                        }
//                    }
//                }

            }
        }
        String result = root.toString();
        File exportFile=new File("./out/indexed");
        File binaryFilePath=new File(binary_path);
        try(FileWriter file=new FileWriter("./out/indexed/"+binaryFilePath.getName()+"_"+Md5+"_"+"_statistic_extracted.json")){
            file.write(result);
            file.flush();
        }
        catch (IOException e){
            e.printStackTrace();
        }
        String slience_string = root_slience.toString();
        File sliencePath=new File(binary_path);
        try(FileWriter file=new FileWriter("./out/indexed/"+sliencePath.getName()+"_"+Md5+"_"+"_slience_extracted.json")){
            file.write(result);
            file.flush();
        }
        catch (IOException e){
            e.printStackTrace();
        }
        long endTime=System.currentTimeMillis();
        System.out.println("This progrem analys time: "+(double)(endTime-startTime)/1000 +"s");
    }

    public String PcodeToString(PcodeOp pOp,FunctionManager fm){
        SavePcode SP=new SavePcode();
        SP.pcode= pOp.getMnemonic();
        Varnode out = pOp.getOutput();
        if (out==null){
            SP.value_type="";
            SP.value_value="";
        }
        else {
            SP.value_type = out.getAddress().getAddressSpace().getName();
            SP.value_value = "0x" + Long.toHexString(pOp.getOutput().getOffset());
        }
        Varnode[] input = pOp.getInputs();

        if (SP.pcode.equals("CALL")){
            SP.param1_type =input[0].getAddress().getAddressSpace().getName();
            SP.param1_value=fm.getFunctionAt(input[0].getAddress()).getName();
        }
        else {
            SP.param1_type = input[0].getAddress().getAddressSpace().getName();
            SP.param1_value = "0x" + Long.toHexString(input[0].getOffset());
        }
        if (input.length<=1){
            SP.param2_type="";
            SP.param2_value="";
        }
        else {
            SP.param2_type = input[1].getAddress().getAddressSpace().getName();
            SP.param2_value = "0x" + Long.toHexString(input[1].getOffset());
        }
        return SP.toString();
    }
    public boolean contine_equal(ClangStatement call_statement){
        boolean flag=false;
        for(int i=0;i<call_statement.numChildren();i++){
            ClangNode child = call_statement.Child(i);
            if (child.toString().equals("="))flag=true;
        }
        return flag;
    }
//    public List<ClangToken>  GetFunctionParamToken(List<ClangToken> tokens){
//        List<ClangToken> result=new ArrayList<>();
//        boolean flag_equal=false;
//        for(ClangToken token:tokens){
//            if(token.Parent())
//        }
//        if(tokens.contains("="))
//            flag_equal=true;
//        if (flag_equal){
//            for(Get)
//        }
//    }
    public void SourceSlience(ClangToken token, ClangTokenGroup chroot,Func funcinfo,boolean start) throws Exception {
        /*给定当前变量的varnode，通过源代码获取在二进制函数内的变量切片
         * 1、首先获取该varnode的地址，通过地址获取变量->获取二进制函数中所有对该变量的引用func_same_token
         * 2、遍历每处引用，在二进制函数内，varnode的位置开始向上追踪
         * 3、在每个引用点获取语句，找到语句中引用的变量，常量，操作符
         * 4、对其中的变量递归
         *  */
        assert token instanceof ClangVariableToken;
        int aa;
        if (token.Parent().toString().contains("FUN_0001d6f4"))
//        if (token.toString().equals("DAT_0003559c"))
            aa=0;
        ArrayList<ClangNode> func_same_token = new ArrayList<ClangNode>();
        cnodeList=new ArrayList<>();
        getClangNode(chroot);
        if(token.getSyntaxType()!= CONST_COLOR) {
            for (ClangNode Cnode : cnodeList) {//获取函数中所有对token变量的引用      可以通过迭代获取parent获取相同的token，应该会更准确
                if (Cnode.equals(token)) break;
                if (Cnode.toString().equals(token.toString())) {
                    func_same_token.add(0, Cnode);
//                    func_same_token.add(Cnode);
                }
            }
        }
        else{//可能当前变量为常量,从入口引入
            source_slience.add(token);
            return;
        }
        if (func_same_token.size()>0) {//这里可以添加变量类型的检测
//            ArrayList<ClangToken> refs = new ArrayList<ClangToken>();
            ArrayList<ArrayList<ClangToken>> refs_inst = new ArrayList<ArrayList<ClangToken>>();
            ClangNode Cnode = null;
            for (ClangNode sametoken : func_same_token) {
                ArrayList<ClangToken> tmp_refs = new ArrayList<ClangToken>();
                Cnode = sametoken;
                if(!(sametoken instanceof ClangVariableToken))continue;
                tmp_refs = get_ref((ClangToken) sametoken, start);
//                if (tmp_refs.size()!=0) break;
                refs_inst.add(tmp_refs);
            }
            for(ArrayList<ClangToken> refs:refs_inst) {
                for (ClangToken ref : refs) {
                    if (source_slience.contains(ref)) continue;
                    source_slience.add(ref);
//                    print("st:    " + ref.Parent().toString());
//                    print("slience: " + source_slience);
                    if (ref.getSyntaxType() == ClangToken.CONST_COLOR) {
                        continue;
                    } else if ((ref.getSyntaxType() == ClangToken.VARIABLE_COLOR) | ((ref.getSyntaxType() == GLOBAL_COLOR))) {
                        SourceSlience(ref, chroot, funcinfo, false);
                    }
                    if (ref.getSyntaxType() == PARAMETER_COLOR && FuncDeep < config.FuncDeep) {
                        FuncDeep += 1;
                        Reference[] references = getReferencesTo(funcinfo.func.getEntryPoint());
                        for (Reference reference : references) {
                            Address fromaddr = reference.getFromAddress();
                            Function referencefunction = getFunctionContaining(fromaddr);
                            if(referencefunction==null)return;
                            if (referencefunction == funcinfo.func) continue;

                            Func tmp_funcinfo = new Func();
                            tmp_funcinfo.func = referencefunction;
//                            print(referencefunction.getName());

                            ClangTokenGroup cur_chroot=null;
                            if (this.chroot_map.containsKey(referencefunction.getEntryPoint())) {
                                cur_chroot= (ClangTokenGroup) this.chroot_map.get(referencefunction.getEntryPoint());
                            }else{
                                DecompileResults res = ifc.decompileFunction(referencefunction, 60, monitor);
                                cur_chroot = res.getCCodeMarkup();   //获取速度慢，需要缓存
                                this.chroot_map.put(referencefunction.getEntryPoint(), cur_chroot);
                            }
                            List<ClangToken> tokens = DecompilerUtils.getTokens(cur_chroot, fromaddr);

//                            List<ClangToken> tokens = DecompilerUtilsMe.getTokens(cur_chroot, fromaddr);//函数有问题
                            if (referencefunction != null && !referencefunction.isThunk()) {
//                            Instruction frominst = getInstructionAt(fromaddr);
                                String nums = ref.toString().replace("param_", "");
                                int num = Integer.parseInt(nums);
//                                print(ref.toString());
                                List<ClangToken> fromtokens = GegIParam(tokens, num - 1);

                                for (ClangToken fromtoken : fromtokens)
                                    SourceSlience(fromtoken, cur_chroot, tmp_funcinfo, false);
                            }
                        }
                    }
                }
            }
        }//当前函数内每个token都追踪完毕
    }
//    public List<ClangToken>  GetTokenFromAddr(ClangTokenGroup cur_chroot,Address addr){
//        for (int i = 0; i < cur_chroot.numChildren(); i++) {
//            ClangNode child = cur_chroot.Child(i);
//            child.g
//            if (!(chroot.Child(i) instanceof ClangTokenGroup)){
//                if (child instanceof  ClangSyntaxToken) continue;//空格，运算符等
//                if (child instanceof  ClangBreak) continue; //缩进
//                if (child instanceof  ClangOpToken) continue;  //操作符  =，*
//                if (child instanceof  ClangTypeToken) continue;//变量类型
//                this.cnodeList.add(child);
////                System.out.println(child);
//            }
//            else
//                getClangNode((ClangTokenGroup) child);
//        }
//    }
    public List<ClangToken> GegIParam(List<ClangToken> tokens,int i){
        boolean is_call=false;
        int num=0;
        List<ClangToken> result = new ArrayList<>();
//        for (ClangToken token:tokens){
        assert tokens.size()!=0;
//        print(tokens.toString());
//        printf(" %d",i);
        if (tokens.size()==0)return result;//有些token获取不到
        ClangNode exp = tokens.get(0).Parent();
        for (int ichild = 0; ichild < exp.numChildren(); ichild++) {
//            print(exp.toString());
//            printf("%d  %d",ichild,exp.numChildren());

            ClangNode child = exp.Child(ichild);
            if (!(child instanceof ClangToken )) {
                continue;
            }
            ClangToken token = (ClangToken)child;

//        for(ClangToken token:tokens[0].Parent())
            if (token instanceof ClangFuncNameToken){
                is_call=true;
            }
            if(is_call){
                if (token.toString().equals(","))
                    num+=1;
                if (token instanceof ClangVariableToken && num==i){
                    result.add(token);
                }
            }
        }
        return result;
    }

//    public void SourceSlience(ArrayList<ClangToken> ListToken) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
//        for()
//    }

    private ArrayList<ClangToken> get_ref(ClangToken token,boolean start) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        /*
        判断token在其所在的语句中是否被引用
        如果token被引用，返回对token赋值或返回
        * */
        ArrayList<ClangToken> result = new ArrayList<ClangToken>();
        if (!(token.Parent() instanceof ClangStatement)) {//所在指令非指令:定义变量
            result.add(token);
            return result;
        }
        //        if(token.Parent() instanceof ClangTokenGroup) {//某个token的parent可能为整个函数，或者一个块
        //            result.add(token);
        //            return result;
        //        }
        ClangNode exp = token.Parent();

        ArrayList<ClangToken> prev = new ArrayList<ClangToken>();
        ArrayList<ClangToken> after = new ArrayList<ClangToken>();
        boolean Iscall_statement = false;
        boolean equl_flag = false;
        if (token.Parent() instanceof ClangVariableDecl) {//token所在的指令为定义变量
            prev.add(token);
        } else if ((((ClangStatement) token.Parent()).getPcodeOp()!=null &&
                ((ClangStatement) token.Parent()).getPcodeOp().getOpcode() == PcodeOp.CALL) ||
                ( token.getPcodeOp()!=null&&
                        token.getPcodeOp().getOpcode() == PcodeOp.CALL)) {//函数调用
            Iscall_statement = true;
            equl_flag = read_write(exp, prev, after, equl_flag);
        } else if (exp.toString().contains("=") && !exp.toString().contains("==")) {//赋值语句
            equl_flag = read_write(exp, prev, after, equl_flag);

        } else {// 如果遇到控制语句
            after.add(token);
        }

        //token在等号左边，追踪等式左边和右边的变量  var=xxxxxx,var[index]=xxxx
        //token在等号右边，不管       xxxx=var   xxxx=func(var,xxxx)
        //        if(equl_flag){
        assert prev.contains(token) | after.contains(token);
        if (prev.contains(token)) {//token在等号左边  out
            result.addAll(prev);
            for (ClangToken A : after) {
                if (!result.contains(A))
                    result.addAll(after);
            }

        } else if (after.contains(token)) {//in
            if (Iscall_statement) {
                //                result.addAll(after);

                result.add(token);//是函数调用
            }
        }
        if (!config.TraceOneFStart) {//避免追踪同一个变量多次
            if (result.contains(token)) {
                result.remove(token);
            }
        }
//            if(result.size()==0){//当前token为out，继续向上迭代
//                result.add(token);
//            }

//            println("token:  "+token.toString());
//            println("result:  "+result.toString());
//            println();

        return result;
    }

    private boolean read_write(ClangNode exp, ArrayList<ClangToken> prev, ArrayList<ClangToken> after, boolean equl_flag) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        //给定一个函数或语句，prev表示等号前面，一般为out；  等号后面为after，一般为in
        FuncTypeStruct currFunctype = null;
//        ArrayList<Tuple<ClangToken, Integer>> tmp_prev = new ArrayList<>();// <ClangToken> tmp_prev = new ArrayList<>();
        ArrayList<FuncParam> tmp_prev = new ArrayList<>();
        ArrayList<FuncParam> tmp_after = new ArrayList<>();
//        ArrayList<Tuple<ClangToken, Integer>> tmp_after = new ArrayList<>();
        ClangToken call_name = null;
        boolean flag_call_name = false;
        boolean fun_flag = false;
        ArrayList<ClangToken> token_list = new ArrayList<>();
        int param_index = -1;
        if (exp.toString().contains("=") && !exp.toString().contains("==")) {//包含等于号
            equl_flag = false;

            for (int i = 0; i < exp.numChildren(); i++) {//遍历每个token
                ClangToken child = (ClangToken) exp.Child(i);
                if (child.toString().equals("=")) {//遇到等号
                    equl_flag = true;
                }
                if (child.getSyntaxType() == FUNCTION_COLOR) {//遇到函数，后面变量为函数参数
                    fun_flag = true;
                    param_index = 0;
                    assert call_name == null;
                    call_name = child;
                    currFunctype = functype.getClass(call_name.toString());
                    if (currFunctype == null)
                        currFunctype = new FuncTypeStruct(call_name.toString(), FuncTypeEnum.typeEnum.Data, functype.get_list(0, 50), config.func_param);//参数全部设为out
                }
                if (equl_flag) {//等号之后 after,in
                    if (child.toString().equals(","))
                        param_index += 1;
                    if ((exp.Child(i) instanceof ClangVariableToken) |
                            child.getSyntaxType() == GLOBAL_COLOR |
                            child.getSyntaxType() == CONST_COLOR) {
                        tmp_after.add(new FuncParam(child, param_index));
                    }
                } else {//等号之前,prev,out
                    if ((exp.Child(i) instanceof ClangVariableToken) |
                            child.getSyntaxType() == GLOBAL_COLOR |
                            child.getSyntaxType() == CONST_COLOR) {
                        tmp_prev.add(new FuncParam(child, param_index));
                    }
                }
            }
        } else {//语句不包含等号
            for (int i = 0; i < exp.numChildren(); i++) {//遍历每个token
                ClangToken child = (ClangToken) exp.Child(i);

                if (child.getSyntaxType() == FUNCTION_COLOR) {//遇到函数，后面变量为函数参数

                    fun_flag = true;
                    param_index = 0;
                    assert call_name == null;
                    call_name = child;

                    currFunctype = functype.getClass(call_name.toString());
                    if (currFunctype == null)
                        currFunctype = new FuncTypeStruct(call_name.toString(), FuncTypeEnum.typeEnum.Data,functype.get_list(0, 50),config.func_param);//参数全部设为out
                }
                if (fun_flag && child.toString().equals(","))
                    param_index += 1;
                if ((exp.Child(i) instanceof ClangVariableToken) |
                        child.getSyntaxType() == GLOBAL_COLOR |
                        child.getSyntaxType() == CONST_COLOR) {
                    tmp_prev.add(new FuncParam(child, param_index));
                }

            }
        }


//        for (int i = 0; i < exp.numChildren(); i++) {//遍历每个token
//            ClangToken child = (ClangToken) exp.Child(i);
//
//            if (!(child.toString().equals("="))) {
//                if (child.getSyntaxType() == FUNCTION_COLOR) {//函数名
//                    call_name = child;
//                    flag_call_name=true;
//                }
//                if (call_name != null) {
//                    if (flag_call_name) {//获取该函数信息
//                        flag_call_name=false;
//                        currFunctype = functype.getClass(call_name.toString());
//                        if (currFunctype == null)
//                            currFunctype = new FuncTypeStruct(call_name.toString(), FuncTypeEnum.typeEnum.Data, List.of(),functype.get_list(0, 50));
//                    }
//                    if (!equl_flag) {//等号之前为out
//                        if ((exp.Child(i) instanceof ClangVariableToken) |
//                                child.getSyntaxType() == GLOBAL_COLOR |
//                                child.getSyntaxType() == CONST_COLOR) {
//                            tmp_prev.add(child);
//                        }
//                    } else {//等号之后为in
//                        if ((exp.Child(i) instanceof ClangVariableToken) |
//                                child.getSyntaxType() == GLOBAL_COLOR |
//                                child.getSyntaxType() == CONST_COLOR) {
//                            if (currFunctype.type == FuncTypeEnum.typeEnum.Control) {
//                                break;
//                            }
//                            tmp_after.add(child);
//                        }
//                    }
//                } else {//还没有函数调用token（不可能在等号之后）
//                    if (!equl_flag) {//等号之前为out
//                        if ((exp.Child(i) instanceof ClangVariableToken) |
//                                child.getSyntaxType() == GLOBAL_COLOR |
//                                child.getSyntaxType() == CONST_COLOR) {
//                            prev.add(child);
//                        }
//                    } else {//等号之后为in
//                        if ((exp.Child(i) instanceof ClangVariableToken) |
//                                child.getSyntaxType() == GLOBAL_COLOR |
//                                child.getSyntaxType() == CONST_COLOR) {
//                            after.add(child);
//                        }
//                    }
//                }
//            } else
//                equl_flag = true;
//        }

        if (call_name != null) {
            if (equl_flag == true) {//有等号
                for (FuncParam item : tmp_prev) {
                    prev.add(item.ct);
                }

                int after_index = 0;
                for (int index : currFunctype.out) {//out
                    if (index > param_index) break;
                    boolean added = false;
                    for (; after_index < tmp_after.size(); after_index++) {
                        if (tmp_after.get(after_index).IndexParam == index) {
                            prev.add(tmp_after.get(after_index).ct);
                            added = true;
                        } else {
                            if (added == true) {
                                after_index -= 1;
                                break;
                            }
                        }
                    }
                }
                after_index = 0;
                for (int index : currFunctype.in) {//out
                    if (index > param_index) break;
                    boolean added = false;
                    for (; after_index < tmp_after.size(); after_index++) {
                        if (tmp_after.get(after_index).IndexParam == index) {
                            after.add(tmp_after.get(after_index).ct);
                            added = true;
                        } else {
                            if (added) {
                                after_index -= 1;
                                break;
                            }
                        }
                    }
                }
            }

            if (equl_flag == false) {//没有等号，结果在prev里
                int after_index = 0;
                for (int index : currFunctype.out) {//out
                    if (index > param_index) break;
                    boolean added = false;
                    for (; after_index < tmp_prev.size(); after_index++) {
                        if (tmp_prev.get(after_index).IndexParam == index) {
                            prev.add(tmp_prev.get(after_index).ct);
                            added = true;
                        } else {
                            if (added == true) {
                                after_index -= 1;
                                break;
                            }
                        }
                    }
                }
                after_index = 0;
                for (int index : currFunctype.in) {//out
                    if (index > param_index) break;
                    boolean added = false;
                    for (; after_index < tmp_prev.size(); after_index++) {
                        if (tmp_prev.get(after_index).IndexParam == index) {
                            after.add(tmp_prev.get(after_index).ct);
                            added = true;
                        } else {
                            if (added) {
                                after_index -= 1;
                                break;
                            }
                        }
                    }
                }
            }
        }else{//不含函数调用的赋值指令
            if (equl_flag == true) {//有等号
                for (FuncParam item : tmp_prev) {
                    prev.add(item.ct);
                }
                for(FuncParam item : tmp_after){
                    if (prev.contains(item.ct))continue;
                    after.add(item.ct);
                }
            }
        }
//        println("st:   "+exp.toString());
//        println("prev: "+prev.toString());
//        println("after: "+after.toString());
        return equl_flag;
    }


    private DecompInterface getDecompInterface() throws DecompileException {
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(this.getCurrentProgram())) {
            throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
        }
        return ifc;
    }

    public void getClangNode(ClangTokenGroup chroot) throws Exception{
        if (chroot==null) return;
        for (int i = 0; i < chroot.numChildren(); i++) {
            ClangNode child = chroot.Child(i);
            if (!(chroot.Child(i) instanceof ClangTokenGroup)){
                if (child instanceof  ClangSyntaxToken) continue;//空格，运算符等
                if (child instanceof  ClangBreak) continue; //缩进
                if (child instanceof  ClangOpToken) continue;  //操作符  =，*
                if (child instanceof  ClangTypeToken) continue;//变量类型
                this.cnodeList.add(child);
//                System.out.println(child);
            }
            else
                getClangNode((ClangTokenGroup) child);
        }
    }
    private String getString(Address addr) throws Exception {
        Memory mem = currentProgram.getMemory();
        StringBuilder core_name_str = new StringBuilder(new String(""));
        while (true) {
            byte geted = mem.getByte(addr.add(core_name_str.length()));
            if (geted == (byte)0){
                return core_name_str.toString();
            }
            core_name_str.append(geted);
        }
    }
}