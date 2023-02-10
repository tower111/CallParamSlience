import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import utils.opcodetype;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;




public class FU_result {
    public Vector<Fu> fus = new Vector<Fu>();
    //    public WString binary;
    Vector<PcodeOp> OneParamSlience ;
    public Opcodes opcodes=new Opcodes();

    public Vector<PcodeBlockBasic> prev_blocks = new Vector<PcodeBlockBasic>();
    public  void GetPrevBlock(PcodeBlockBasic curr_block){
    /*从一个基本块获取*/
        for (int i=0;i<curr_block.getInSize();i++){
            PcodeBlockBasic in_block = (PcodeBlockBasic) curr_block.getIn(i);
            if (prev_blocks.contains(in_block)){//元素存在不再添加
                continue;
            }
            prev_blocks.add(in_block);
            GetPrevBlock(in_block);
        }
    }

    public void Getref(PcodeOp op){
        long addr = op.getInput(0).getOffset();//基地址，一般是寄存器
        int off = (int) op.getInput(1).getOffset();//获取偏移量
        PcodeBlockBasic curr_block = op.getParent();
        GetPrevBlock(curr_block);//迭代获取基本块的前继
        Vector<PcodeOp> get_unique_list=new  Vector<PcodeOp>();//保存计算栈变量生成的中间变量
        Vector<PcodeOp> Store_list=new  Vector<PcodeOp>();//保存store指令
        Vector<PcodeOp> PTRADD_list=new  Vector<PcodeOp>();//保存ptr_add指令

        for (Iterator<PcodeOp> it = curr_block.getIterator(); it.hasNext(); ) {//当前基本块
            PcodeOp prevOp = it.next();
            if (op.getSeqnum() == prevOp.getSeqnum())
                break;
            if(addr==prevOp.getInput(0).getOffset() && off==(int) prevOp.getInput(1).getOffset()){
                get_unique_list.add(prevOp);
            }
            if(prevOp.getOpcode()==PcodeOp.STORE){
                Store_list.add(prevOp);
            }
            else if(prevOp.getOpcode()==PcodeOp.PTRADD){
                PTRADD_list.add(prevOp);
            }
        }
        for( PcodeBlockBasic pb:prev_blocks){//当前函数前继基本块
            for (Iterator<PcodeOp> it = pb.getIterator(); it.hasNext(); ) {//当前基本块
                PcodeOp prevOp = it.next();
                if(addr==prevOp.getInput(0).getOffset() && off==(int) prevOp.getInput(1).getOffset()){
                    get_unique_list.add(prevOp);
                }
                if(prevOp.getOpcode()==PcodeOp.STORE){
                    Store_list.add(prevOp);
                }
                else if(prevOp.getOpcode()==PcodeOp.PTRADD){
                    PTRADD_list.add(prevOp);
                }
            }
        }

        for(PcodeOp unique_inst:get_unique_list){

            Varnode unique_vnode = unique_inst.getOutput();
            for(PcodeOp PTRADD:PTRADD_list){
                if (PTRADD.getInput(0)==unique_vnode){

                }
            }
        }




//            Vector<PcodeBlock> PrevBlocks = GetPrevBlock(curr_block);

    }
    public void mem_slience(PcodeOp op){
        if (op.getOpcode()==PcodeOp.LOAD){
            Varnode addr = op.getInput(0);//获取地址
            Varnode off = op.getInput(1);//获取偏移量
            HighVariable high_var = addr.getHigh();
        }
        if (op.getOpcode()==PcodeOp.PTRSUB){//pushsub指令用来

            Getref(op);

//            HighVariable high_var = addr.getHigh();
        }
    }
    public boolean get_fu(Varnode node) throws ClassNotFoundException, InstantiationException, IllegalAccessException {

        PcodeOp definst = node.getDef();

        if(definst==null){
            System.out.println(node);
            return false;
        }
        System.out.println(definst);
        if (definst.getOpcode()==PcodeOp.INDIRECT || definst.getOpcode()==PcodeOp.MULTIEQUAL ){//不需要追踪这两种变量
            return false;
        }
        if (OneParamSlience.size() > 1000) {//限制变量长度
            return false;
        }
        opcode instinfo = Opcodes.getClass(definst.getMnemonic());
        assert instinfo != null;
        if (instinfo.type.equals(opcodetype.typeEnum.Control)|| instinfo.type.equals(opcodetype.typeEnum.Brance)) {//不追踪控制语句
            /*可以在这里添加控制语句的追踪规则*/
            return false;
        }

        OneParamSlience.add(definst);
        if (instinfo.type.equals(opcodetype.typeEnum.Mem)) {//内存变量
            /*对内存地址的追踪 待补充*/

            Varnode[] input = definst.getInputs();//获取值来源
            mem_slience(definst);//获取指针来源
            for(Varnode def:input) {
                get_fu(def);
            }


        }

        else if (instinfo.type.equals(opcodetype.typeEnum.Data)) {//数据变量
            /*数据变量的追踪规则：
            * 转移指令，运算指令被认为是数据指令
            * */
            Varnode[] input = definst.getInputs();
            for(Varnode def:input) {
                get_fu(def );
            }
        }
        else if (instinfo.type.equals(opcodetype.typeEnum.Func)) {//函数调用
            Varnode[] input = definst.getInputs();
            Varnode[] params =Arrays.copyOfRange(input,1,input.length);
            for(Varnode def:params) {
                get_fu(def );
            }
        }



        Varnode[] input = definst.getInputs();
        for(Varnode def:input) {
            get_fu(def );
        }



        return true;
    }
}
