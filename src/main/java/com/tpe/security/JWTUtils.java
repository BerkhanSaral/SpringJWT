package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtils {

    private long expirationTime=86400000;//24*60*60*1000

    private String secretKey="techpro";

    //token: header + payload(userla ilgili bilgileri) + signature
    // Bearer eysdxGCFGLPHFG12gfhg

    //1-JWT token generate:içine username koyacağız
    public String generateToken(Authentication authentication){

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        //login olan kullanıcıyoı getirir

        //tokenın içine username bilgisini koyalım
        return Jwts.builder()//jwt oluşturucuyu getirir
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())//System.currentMillis()-->24.08 21.09
                .setExpiration(new Date(new Date().getTime()+expirationTime))//-->25.08 21.09
                .signWith(SignatureAlgorithm.HS512,secretKey)
                //hash fonk ile tek yönlü şifreleme yapılır, karşılaştırma yapılabilir
                .compact();//ayarları tamamlar ve tokenı oluşturur

    }


    //2-JWT tokenı validate
    public boolean validateToken(String token){

        try {
            Jwts.parser()//ayrıştırıcı
                    .setSigningKey(secretKey)//anahtarı set ediyoruz
                    .parseClaimsJws(token);//anahtar uyumlu ise, JWT token geçerli
            return true;
        }catch (ExpiredJwtException e){
            e.printStackTrace();
        }catch (UnsupportedJwtException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (MalformedJwtException e){
            e.printStackTrace();
        }catch (IllegalArgumentException e){
            e.printStackTrace();
        }
        return false;
    }


    //3-JWT tokendan username i alma
    public String getUsernameFromToken(String token){

        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)//doğrulanmış tokenın claimlerini getirir(header,payload,signature)
                .getBody()
                .getSubject();//username
    }


}