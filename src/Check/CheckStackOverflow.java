package Check;

import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import utils.FuncUicorn;
import Check.utils;

import java.io.IOException;
import java.util.ArrayList;

public class CheckStackOverflow {
    public  Check.utils utils;
    public  Check.Reporter reporter;
    public FuncUicorn fu;
    public boolean isVul=false;
    public CheckStackOverflow(FuncUicorn fu,Reporter reporter) throws IOException {
        this.utils=new utils();
        this.reporter=reporter;
        this.fu=fu;
        switch (fu.Fu_funcname){
            case "sprintf":{
                isVul=sprintf();
                break;
            }
            case "strcpy":{
                isVul=strcpy();
                break;
            }
            case "sscanf":{
                isVul=sscanf();
                break;
            }
            default:
                break;
        }
    }



    public boolean strcpy() throws IOException {//检查第二个变量是否来自外部
        assert fu.Fu_funcname.equals("strcpy");
        int level_gl=0;
        ArrayList<ArrayList<ClangToken>> tar = fu.RealSlience.get(0);
        if (tar.size()==0)return false;
        for(int idx=1; idx<fu.RealSlience.size();idx+=1){//每个变量
            for(ArrayList<ClangToken> item:fu.RealSlience.get(idx)){//
                int level=utils.IsExternStringLevel1(item);
                if(level>level_gl) level_gl = level;
            }
        }
        if (level_gl!=0) this.reporter.ReportStackOverFlow(fu, level_gl, "SO");
        return true;
    }

    public boolean sscanf() throws IOException {//检查第一个变量是否来自外部，第二个变量包含%s
        assert fu.Fu_funcname.equals("sscanf");
        ArrayList<ArrayList<ClangToken>> tar = fu.RealSlience.get(0);
        if (tar.size()==0)return false;
        if(utils.IsStrFmt(fu.RealSlience.get(1))==0) return false;
        int level_gl=0;
        for(ArrayList<ClangToken> item:fu.RealSlience.get(0)){//
            int level=utils.IsExternStringLevel1(item);
            if(level>level_gl) level_gl = level;
        }
        if (level_gl!=0) this.reporter.ReportStackOverFlow(fu, level_gl, "SO");
        return true;
    }
    public boolean sprintf() throws IOException {//检查第二个变量后的所有变量是否来自外部，第二个变量包含%s
        assert fu.Fu_funcname.equals("sprintf");
        int level_gl=0;
        if(utils.IsStrFmt(fu.RealSlience.get(1))==0) return false;
        for(int idx=2; idx<fu.RealSlience.size();idx+=1){//每个变量
            for(ArrayList<ClangToken> item:fu.RealSlience.get(idx)){//
//                ArrayList aa = item;
                int level=utils.IsExternStringLevel1(item);
                if(level>level_gl) level_gl = level;

            }
        }
        if (level_gl!=0) this.reporter.ReportStackOverFlow(fu, level_gl, "SO");

        return true;
    }



}
