package com.trinoudf.secret;

import io.trino.spi.Plugin;
import com.google.common.collect.ImmutableSet;
import java.util.Set;

public class SecretPlugin  implements Plugin {
    @Override
    public Set<Class<?>> getFunctions(){
        return ImmutableSet.<Class<?>>builder()
                .add(SecretFunctions.class)
                .add(PrestoEncryptAES.class)
                .add(PrestoDecryptAES.class)
                .build();
    }
}
