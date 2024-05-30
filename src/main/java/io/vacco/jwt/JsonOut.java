package io.vacco.jwt;

public interface JsonOut {

  <T> String toJson(T t);

}
