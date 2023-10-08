package Check;

import ghidra.app.decompiler.ClangToken;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Locale;

import utils.FuncUicorn;

import static ghidra.app.decompiler.ClangToken.CONST_COLOR;

public class CmdInject {

    public Check.utils utils;
    public Check.Reporter reporter;

    public FuncUicorn fu;
    public boolean isVul = false;

    public CmdInject(FuncUicorn fu, Reporter reporter) throws IOException {
        this.utils = new utils();
        this.reporter = reporter;
        this.fu = fu;
        switch (fu.Fu_funcname) {
            case "system":
            case "snprintf":
            case "sprintf": {
                isVul = system();
                break;
            }
            default:
                break;
        }
        if (fu.Fu_funcname.toLowerCase().contains("exe")){
            isVul = system();
        }
        else if(fu.Fu_funcname.toLowerCase().contains("run")&& fu.Fu_funcname.toLowerCase().contains("cmd")){
            isVul = system();
        }
    }
//    public boolean formatCMd throws IOException{
//        ArrayList<ArrayList<ClangToken>> fmt = fu.RealSlience.get(0);
//        if (fmt.size() == 0) return false;
//    }

    public boolean system() throws IOException {//命令来自外部
//        assert fu.Fu_funcname.equals("system");
        ArrayList<ArrayList<ClangToken>> fmt = fu.RealSlience.get(0);
        if (fmt.size() == 0) return false;
//        if (!fmt.get(0).contains("%s")) {
//            return false;
//        }
        int level=0;
        int level_fmtcmd=0;
        for (int idx = 0; idx < fu.RealSlience.size(); idx += 1) {//每个变量

            for (ArrayList<ClangToken> item : fu.RealSlience.get(idx)) {//
//                ArrayList aa = item;
//                if(item.size()<=2 && item.get(0).getSyntaxType()==CONST_COLOR) return false;
                if(item.get(0).getSyntaxType()==CONST_COLOR) continue;
                int tmp_cmd_level=utils.IsExternStringLevel1(item);
                if (tmp_cmd_level>level)level =tmp_cmd_level;
                if (fu.Fu_funcname.equals("sprintf")|| fu.Fu_funcname.equals("snprintf")){
                    int tmp_level_fmtcmd=utils.IsCMD(item);
                    if(tmp_level_fmtcmd>level_fmtcmd)level_fmtcmd=tmp_level_fmtcmd;
                }
            }
            if (fu.Fu_funcname.equals("sprintf")|| fu.Fu_funcname.equals("snprintf")){
                if(level_fmtcmd!=0 && level !=0){
                    this.reporter.ReportStackOverFlow(fu, level,"CI");
                    return true;
                }
            }
            else {
                if (level != 0) {
                    this.reporter.ReportStackOverFlow(fu, level,"CI");
                    return true;
                }
            }
        }

        return false;
    }


}

