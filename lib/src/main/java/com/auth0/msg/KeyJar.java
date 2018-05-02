package com.auth0.msg;

import java.util.ArrayList;
import java.util.List;

public class KeyJar {
    List<KeyBundle> keyBundles;
    public void addKeyBundle(String owner, KeyBundle kb) {
    }
    public KeyBundle getKeyBundle(){
        return new KeyBundle();
    }

    public List<Key> getKeys(){
        List<Key> allKeys = new ArrayList<Key>();;
        for(KeyBundle kb: keyBundles) {
            allKeys.addAll(kb.getKeys());
        }
        return allKeys;
    }
}
