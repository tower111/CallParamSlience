package utils;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;

import java.util.List;

public class FuncParam {
    public ClangToken ct;     //函数名
    public int IndexParam;   //函数种类

    public FuncParam(ClangToken ct,int IndexParam) {
        this.ct = ct;
        this.IndexParam = IndexParam;
    }
}
