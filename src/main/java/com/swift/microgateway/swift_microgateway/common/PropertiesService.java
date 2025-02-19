package com.swift.microgateway.swift_microgateway.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class PropertiesService {

    @Autowired
    private Environment env;

    @Value("${external.swift-uri}")
    public static String t1;

    public String getPropertyValue(String key) {
        String returnValue = "No value";

        String keyValue = env.getProperty(key);

        if (keyValue != null && !keyValue.isEmpty()) {
            returnValue = keyValue;
        }
        return returnValue;
    }
}
