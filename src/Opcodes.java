import utils.opcodetype;

import java.lang.reflect.Field;

public class Opcodes {
    public opcode COPY=new opcode("COPY", opcodetype.typeEnum.Data);
    public opcode LOAD=new opcode("LOAD", opcodetype.typeEnum.Mem);
    public opcode STORE=new opcode("STORE", opcodetype.typeEnum.Mem);
    public opcode 	BRANCH=new opcode("BRANCH", opcodetype.typeEnum.Brance);
    public opcode CBRANCH=new opcode("CBRANCH", opcodetype.typeEnum.Brance);
    public opcode BRANCHIND=new opcode("BRANCHIND", opcodetype.typeEnum.Brance);
    public opcode CALL=new opcode("CALL", opcodetype.typeEnum.Func);
    public opcode CALLIND=new opcode("CALLIND", opcodetype.typeEnum.Func);
    public opcode USERDEFINED=new opcode("USERDEFINED", opcodetype.typeEnum.Other);
    public opcode RETURN=new opcode("RETURN", opcodetype.typeEnum.Data);
    public opcode PIECE=new opcode("PIECE", opcodetype.typeEnum.Data);
    public opcode SUBPIECE=new opcode("SUBPIECE", opcodetype.typeEnum.Data);
    public opcode INT_EQUAL=new opcode("INT_EQUAL", opcodetype.typeEnum.Control);
    public opcode INT_NOTEQUAL=new opcode("INT_NOTEQUAL", opcodetype.typeEnum.Control);
    public opcode INT_LESS=new opcode("INT_LESS", opcodetype.typeEnum.Control);
    public opcode INT_SLESS=new opcode("INT_SLESS", opcodetype.typeEnum.Control);

    public opcode INT_LESSEQUAL=new opcode("INT_LESSEQUAL", opcodetype.typeEnum.Control);
    public opcode INT_SLESSEQUAL=new opcode("INT_SLESSEQUAL", opcodetype.typeEnum.Control);
    public opcode INT_ZEXT=new opcode("INT_ZEXT", opcodetype.typeEnum.Data);
    public opcode INT_SEXT=new opcode("INT_SEXT", opcodetype.typeEnum.Data);
    public opcode INT_ADD=new opcode("INT_ADD", opcodetype.typeEnum.Data);
    public opcode INT_SUB=new opcode("INT_SUB", opcodetype.typeEnum.Data);
    public opcode INT_CARRY=new opcode("INT_CARRY", opcodetype.typeEnum.Control);
    public opcode INT_SCARRY=new opcode("INT_SCARRY", opcodetype.typeEnum.Control);
    public opcode INT_SBORROW=new opcode("INT_SBORROW", opcodetype.typeEnum.Control);
    public opcode INT_2COMP=new opcode("INT_2COMP", opcodetype.typeEnum.Data);
    public opcode INT_NEGATE=new opcode("INT_NEGATE", opcodetype.typeEnum.Data);
    public opcode INT_XOR=new opcode("INT_XOR", opcodetype.typeEnum.Data);
    public opcode INT_AND=new opcode("INT_AND", opcodetype.typeEnum.Data);
    public opcode INT_OR=new opcode("INT_OR", opcodetype.typeEnum.Data);
    public opcode INT_LEFT=new opcode("INT_LEFT", opcodetype.typeEnum.Data);
    public opcode INT_RIGHT=new opcode("INT_RIGHT", opcodetype.typeEnum.Data);

    public opcode INT_SRIGHT=new opcode("INT_SRIGHT", opcodetype.typeEnum.Data);
    public opcode INT_MULT=new opcode("INT_MULT", opcodetype.typeEnum.Data);
    public opcode INT_DIV=new opcode("INT_DIV", opcodetype.typeEnum.Data);
    public opcode INT_REM=new opcode("INT_REM", opcodetype.typeEnum.Data);
    public opcode INT_SDIV=new opcode("INT_SDIV", opcodetype.typeEnum.Data);
    public opcode INT_SREM=new opcode("INT_SREM", opcodetype.typeEnum.Data);
    public opcode BOOL_NEGATE=new opcode("BOOL_NEGATE", opcodetype.typeEnum.Data);
    public opcode BOOL_XOR=new opcode("BOOL_XOR", opcodetype.typeEnum.Data);
    public opcode BOOL_AND=new opcode("BOOL_AND", opcodetype.typeEnum.Data);
    public opcode BOOL_OR=new opcode("BOOL_OR", opcodetype.typeEnum.Data);
    public opcode FLOAT_EQUAL=new opcode("FLOAT_EQUAL", opcodetype.typeEnum.Control);
    public opcode FLOAT_NOTEQUAL=new opcode("FLOAT_NOTEQUAL", opcodetype.typeEnum.Control);
    public opcode FLOAT_LESS=new opcode("FLOAT_LESS", opcodetype.typeEnum.Control);
    public opcode FLOAT_LESSEQUAL=new opcode("FLOAT_LESSEQUAL", opcodetype.typeEnum.Control);
    public opcode FLOAT_ADD=new opcode("FLOAT_ADD", opcodetype.typeEnum.Data);
    public opcode FLOAT_SUB=new opcode("FLOAT_SUB", opcodetype.typeEnum.Data);

    public opcode FLOAT_MULT=new opcode("FLOAT_MULT", opcodetype.typeEnum.Data);
    public opcode FLOAT_DIV=new opcode("FLOAT_DIV", opcodetype.typeEnum.Data);
    public opcode FLOAT_NEG=new opcode("FLOAT_NEG", opcodetype.typeEnum.Data);
    public opcode FLOAT_ABS=new opcode("FLOAT_ABS", opcodetype.typeEnum.Data);
    public opcode FLOAT_SQRT=new opcode("FLOAT_SQRT", opcodetype.typeEnum.Data);
    public opcode FLOAT_CEIL=new opcode("FLOAT_CEIL", opcodetype.typeEnum.Data);
    public opcode FLOAT_FLOOR=new opcode("FLOAT_FLOOR", opcodetype.typeEnum.Data);
    public opcode FLOAT_ROUND=new opcode("FLOAT_ROUND", opcodetype.typeEnum.Data);
    public opcode FLOAT_NAN=new opcode("FLOAT_NAN", opcodetype.typeEnum.Data);
    public opcode INT2FLOAT=new opcode("INT2FLOAT", opcodetype.typeEnum.Data);
    public opcode FLOAT2FLOAT=new opcode("FLOAT2FLOAT", opcodetype.typeEnum.Data);
    public opcode TRUNC=new opcode("TRUNC", opcodetype.typeEnum.Data);
    public opcode CPOOLREF=new opcode("CPOOLREF", opcodetype.typeEnum.Other);
    public opcode NEW=new opcode("NEW", opcodetype.typeEnum.Data);

    public opcode INDIRECT=new opcode("INDIRECT", opcodetype.typeEnum.Direct);
    public opcode MULTIEQUAL=new opcode("MULTIEQUAL", opcodetype.typeEnum.Brance);
    public opcode PTRADD=new opcode("PTRADD", opcodetype.typeEnum.Mem);
    public opcode PTRSUB=new opcode("PTRSUB", opcodetype.typeEnum.Mem);
    public opcode CAST=new opcode("CAST", opcodetype.typeEnum.Data);




    public static opcode getClass(String mnemonic) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        Class<?> clazz= Class.forName("Opcodes");
        Field[] fieldList=clazz.getDeclaredFields();
        Object obj=clazz.newInstance();
        for(Field field:fieldList){
            if(mnemonic.equals((field.getName())))
                return  (opcode)field.get(obj);
        }
        return null;
    }
}
