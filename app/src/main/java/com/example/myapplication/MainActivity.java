package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String containEncryptKeyPem = stringFromJNI("noi dung key pem");
        Log.d("C++", "containEncryptKeyPem: " + containEncryptKeyPem);
    }
    public native static String stringFromJNI(String input);
    static {
        System.loadLibrary("native-lib");
//        System.loadLibrary("ssl");
//        System.loadLibrary("crypto");
    }

}
