package com.sunshinehu.encryption;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

//com_sunshinehu_encryption_MainActivity

public class MainActivity extends Activity implements View.OnClickListener{

    private Button btn1;
    private Button btn2;

    private TextView text;

    private EditText edit;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        btn1= (Button) findViewById(R.id.button);
        btn2= (Button) findViewById(R.id.button2);
        text= (TextView) findViewById(R.id.textView);
        edit= (EditText) findViewById(R.id.editText);

        btn1.setOnClickListener(this);
        btn2.setOnClickListener(this);

    }

    static {

        System.loadLibrary("encryption");

    }

    //加密方法
    private native String  encode(String origin,String code);
    //解密方法
    private native String  decode(String result,String code);


    @Override
    public void onClick(View view) {
        if(view.getId()==R.id.button){
            text.setText(encode(edit.getText().toString(),android.os.Build.SERIAL));
        }else if(view.getId()==R.id.button2){
            text.setText(decode(edit.getText().toString(),android.os.Build.SERIAL));
        }
    }
}
