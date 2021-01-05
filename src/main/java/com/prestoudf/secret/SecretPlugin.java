package com.prestoudf.secret;

import io.prestosql.spi.Plugin;
import com.google.common.collect.ImmutableSet;
import java.util.Set;

public class SecretPlugin  implements Plugin {
    @Override
    public Set<Class<?>> getFunctions(){
        SecretFunctions.setKeys();
        return ImmutableSet.<Class<?>>builder()
                .add(SecretFunctions.class)
                .build();
    }
}
