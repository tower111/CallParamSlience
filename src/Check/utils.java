package Check;

import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;

import java.util.ArrayList;

import static ghidra.app.decompiler.ClangToken.CONST_COLOR;

public class utils {
    public String[]  cmdString={"bin/","/dev","/var","/tmp","/etc","/sbin","htdocs",".tar",".gz","ping",".php",".js"};
    public String[]  StringMetiod={"strstr","strcmp","strncmp","strcat","str","chr"};
    public String[]  fmtStrMethod={"write"};
    public String Reason="";
    public String[]  KeyExternString={"username","Content-Type","Content-Length","POST","GET","Host"};//获取网络相关字符串的方法，需要扩展
    public String[]  KeyExternAddr={};//从外部获取数据的地址
    public String[]  KeyExternCall={"getenv","websGetVar"};//从外界获取数据的函数名
    public String[] badString={"atoi","itoa"};//遇到这些字符串大概率不存在漏洞
    public int IsExternS(ClangToken token){
        String tokenParent=token.Parent().toString().toLowerCase();
        if (tokenParent.contains("sprintf")||tokenParent.contains("snprintf")){  //这里有点激进，应该是只能确定一个分支不包含漏洞
            boolean varflag = false;
            ArrayList<String> var_list = new ArrayList<>();
            for (int i = 0; i < token.Parent().numChildren(); i++) {
                ClangToken tmpToken = (ClangToken) token.Parent().Child(i);
                if (tmpToken.getSyntaxType() == ClangToken.VARIABLE_COLOR || tmpToken.getSyntaxType() == ClangToken.GLOBAL_COLOR ) {
                    var_list.add(tmpToken.toString());
                }
                if(tmpToken.getSyntaxType() == CONST_COLOR){
                    if(tmpToken.toString().contains("%s")){
                        varflag=true;
                    }
                }
            }
            if(!varflag || var_list.size()<=1){ //token所在的指令，如果为调用sprint、snprintf函数，则必须包含%s且包含至少一个字符串
                this.Reason = "遇到没问题的snprintf终止";
                return 0;
            }
        }
        for(String sm:badString){   //同上，激进的处理
            if(tokenParent.contains(sm) ){
                //假设如果一个分支为int，则其他分支也一定为int，这是合理的
                this.Reason = "遇到badString终止";
                return 0;
            }
        }

        for(String sm:StringMetiod){
            if(tokenParent.contains(sm) ){
                this.Reason = "字符串处理方法";
                return 1;
            }
        }
        for(String fsm:fmtStrMethod) {
            if (tokenParent.contains(fsm) && tokenParent.contains("%s")) {
                this.Reason = "字符串格式化方法";
                return 1;
            }
        }

        this.Reason = "危险字符串或函数";
        for(String ks:KeyExternString){
            if(tokenParent.contains(ks.toLowerCase())){return 2;}
        }
        for(String ks:KeyExternAddr){
            if(tokenParent.contains(ks.toLowerCase())){return 2;}
        }
        for(String ks:KeyExternCall){
            if(tokenParent.contains(ks.toLowerCase())){return 2;}
        }
        return 0;
    }
/*
    v13 = inet_ntoa(v11);
    strcpy(&s2[v51], v13);   非外部

    sprintf(command, "mv %s %s\n", "/data2/swtp_image_upload", "/var/log/swtp-image");
    system(command);



 */
    public int IsStrFmt(ArrayList<ArrayList<ClangToken>> OneParam){ //格式化方式是否为字符串
        if (OneParam.size()==0) return 0;
        for(ClangToken token:OneParam.get(0)){
            if (token.Parent() instanceof ClangStatement){
                String tokenParent=token.Parent().toString().toLowerCase();
                if(tokenParent.contains("%s")){
                    return 1;
                }
            }
        }
        return 0;
    }

    public int IsExternStringLevel1(ArrayList <ClangToken> OneParam){//简单判断该字段是否和字符串相关
        int result=0;
        if (OneParam.size()<=2){//第一个token位危险函数调用中的参数，如果只有两个，第二个应该是常量
            if (OneParam.size()==2 && OneParam.get(1).getSyntaxType()==CONST_COLOR){
                return result;
            }
            else if(OneParam.size()<2){
                return result;
            }

        }
        for(ClangToken token:OneParam){
            if (token.Parent() instanceof ClangStatement){
                String tokenParent=token.Parent().toString().toLowerCase();
                if(tokenParent.contains("\"")){
                    this.Reason = "变量来自外部输入";
                    int tmp_result = IsExternS(token);
                    if(tmp_result>result)result=tmp_result;
                }
            }
        }
        return  result;
    }
    public int IsExternC(ClangToken token){ //在处理的token是否是一个命令
        String tokenParent=token.Parent().toString().toLowerCase();
        if (!tokenParent.contains("%s")) return 0;
        if(tokenParent.contains("HTTP/1.1")) return 0;
        if (tokenParent.contains("/") && tokenParent.contains(".") ){
            return 1;
        }
        for (String item:cmdString){
            if (tokenParent.contains(item))return 2;
        }
        return 0;
    }
    public int IsCMD(ArrayList <ClangToken> OneParam){//判断该变量是否和命令相关
        int result=0;
//        if (OneParam.size()<=2){//第一个token为危险函数调用中的参数，如果只有两个，第二个应该是常量
//            if (OneParam.size()==2 && OneParam.get(1).getSyntaxType()==CONST_COLOR){
//                if(OneParam.contains("%s") && ){
//
//                }
////                return result;
//            }
//            else if(OneParam.size()<2){
//                return result;
//            }
//        }
        for(ClangToken token:OneParam){
            if (token.Parent() instanceof ClangStatement){
                String tokenParent=token.Parent().toString().toLowerCase();
                if(tokenParent.contains("\"")){
                    this.Reason = "变量拼接成命令";
                    result =IsExternC(token); //IsExternS(token);
                }
            }
        }
        return  result;
    }


}
