package Check;

import utils.FuncUicorn;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import static org.python.modules.cmath.e;

public class Reporter {
    public String SaveReport="./out/report/";

    public FileWriter fw;
    public Reporter(String filename) throws IOException {

        String WriteFile=filename;
        this.fw=new FileWriter(WriteFile);

    }
    public void ReportStackOverFlow(FuncUicorn fu,int level,String vul_type) throws IOException {

        String result=fu.toString();
        System.out.printf("触发%s：%s",vul_type,result);
        this.fw.write("level:"+String.valueOf(level)+"  "+vul_type+"\n"+result);
        this.fw.flush();
    }

}
