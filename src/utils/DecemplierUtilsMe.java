package utils;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

import java.util.ArrayList;
import java.util.List;

public class DecemplierUtilsMe {
    public static List<ClangToken> getTokens(ClangNode root, AddressSetView addressSet) {
        List<ClangToken> tokenList = new ArrayList<>();
        collectTokens(tokenList, root, addressSet);
        return tokenList;
    }
    public static List<ClangToken> getTokens(ClangNode root, Address address) {
        AddressSet set = new AddressSet(address);
        return getTokens(root, set);
    }
    private static void collectTokens(List<ClangToken> tokenList, ClangNode parentNode,
                                      AddressSetView addressSet) {
        int nchild = parentNode.numChildren();
        for (int i = 0; i < nchild; i++) {
            ClangNode node = parentNode.Child(i);
            if (node.numChildren() > 0) {
                collectTokens(tokenList, node, addressSet);
            }
            else if (node instanceof ClangToken) {
                ClangToken token = (ClangToken) node;
                if (intersects(token, addressSet)) {
                    tokenList.add((ClangToken) node);
                }
            }
        }
    }
    private static boolean intersects(ClangToken token, AddressSetView addressSet) {
        Address minAddress = token.getMinAddress();
        int dd;
        if(addressSet.getMaxAddress().toString().equals("00014cb8") && token.toString().equals("FUN_0001490c"))
            dd=0;
        if (minAddress == null) {
            return false;
        }
        Address maxAddress = token.getMaxAddress();
        maxAddress = maxAddress == null ? minAddress : maxAddress;

//        System.out.println(addressSet.getMaxAddress().toString());

        if(addressSet.getMaxAddress()==maxAddress|| addressSet.getMaxAddress()==minAddress || addressSet.intersects(minAddress, maxAddress))
            return true;
        return false;
    }
}
