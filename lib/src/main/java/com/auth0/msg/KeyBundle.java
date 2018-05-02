package com.auth0.msg;

import java.util.List;

public class KeyBundle {
    public List<Key> keys;
    public void addKey(Key newKey){
        keys.add(newKey);
    }
    public List<Key> getKeys(){
        return keys;
    }
}
