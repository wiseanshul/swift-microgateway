package com.swift.microgateway.swift_microgateway.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


public class UserLogin {
   private String clintId;
   private String clintSecrets;
   private String scope;

   public UserLogin() {

   }

   public UserLogin(String clintId, String clintSecrets, String scope) {

      this.clintId = clintId;
      this.clintSecrets = clintSecrets;
      this.scope = scope;
   }

   public String getClintId() {
      return clintId;
   }

   public void setClintId(String clintId) {
      this.clintId = clintId;
   }

   public String getClintSecrets() {
      return clintSecrets;
   }

   public void setClintSecrets(String clintSecrets) {
      this.clintSecrets = clintSecrets;
   }

   public String getScope() {
      return scope;
   }

   public void setScope(String scope) {
      this.scope = scope;
   }
}
