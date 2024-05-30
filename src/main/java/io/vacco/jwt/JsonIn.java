package io.vacco.jwt;

import java.io.*;
import java.lang.reflect.Type;
import java.net.URL;

public interface JsonIn {

  <T> T fromJson(Reader r, Type knownType);

  default <T> T fromJson(String s, Type knownType) {
    return fromJson(new StringReader(s), knownType);
  }

}
